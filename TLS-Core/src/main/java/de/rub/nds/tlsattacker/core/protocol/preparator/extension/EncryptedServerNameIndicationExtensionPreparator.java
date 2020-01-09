/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.tlsattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX25519Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX448Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientEsniInnerParser;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientEsniInnerSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareEntrySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedServerNameIndicationExtensionSerializer.EsniSerializerMode;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class EncryptedServerNameIndicationExtensionPreparator extends
        ExtensionPreparator<EncryptedServerNameIndicationExtensionMessage> {

    public static final int AEAD_TAG_LENGTH = 16;
    public static final int AEAD_CCM_8_TAG_LENGTH = 8;
    public static final int AEAD_IV_LENGTH = 12;

    public enum EsniPreparatorMode {
        CLIENT,
        SERVER;
    }

    private static final Logger LOGGER = LogManager.getLogger();

    private final Chooser chooser;
    private final List<CipherSuite> implementedCiphersuites;
    private final List<NamedGroup> implementedNamedGroups;

    private final EncryptedServerNameIndicationExtensionMessage msg;

    private ClientHelloMessage clientHelloMessage;
    private ByteArrayOutputStream streamClientEsniInnerBytes;

    private EsniPreparatorMode esniPreparatorMode;

    public EncryptedServerNameIndicationExtensionPreparator(Chooser chooser,
            EncryptedServerNameIndicationExtensionMessage message,
            ExtensionSerializer<EncryptedServerNameIndicationExtensionMessage> serializer) {
        super(chooser, message, serializer);
        this.msg = message;
        this.chooser = chooser;
        this.streamClientEsniInnerBytes = new ByteArrayOutputStream();

        this.implementedCiphersuites = new LinkedList();
        this.implementedCiphersuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        this.implementedCiphersuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        this.implementedCiphersuites.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        this.implementedCiphersuites.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        this.implementedCiphersuites.add(CipherSuite.TLS_AES_128_CCM_8_SHA256);

        this.implementedNamedGroups = new LinkedList();
        this.implementedNamedGroups.add(NamedGroup.ECDH_X25519);
        this.implementedNamedGroups.add(NamedGroup.ECDH_X448);
        this.implementedNamedGroups.add(NamedGroup.SECP256R1);

        if (!msg.getClientEsniInner().getServerNameList().isEmpty() || msg.getServerNonce() != null) {
            this.esniPreparatorMode = EsniPreparatorMode.CLIENT;
        } else {
            this.esniPreparatorMode = EsniPreparatorMode.SERVER;
        }
    }

    public ClientHelloMessage getClientHelloMessage() {
        return clientHelloMessage;
    }

    public void setClientHelloMessage(ClientHelloMessage clientHelloMessage) {
        this.clientHelloMessage = clientHelloMessage;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing EncryptedServerNameIndicationExtension");
        switch (this.esniPreparatorMode) {
            case CLIENT:
                prepareClientEsniInner(msg);
                prepareClientEsniInnerBytes(msg);
                prepareCipherSuite(msg);
                prepareNamedGroup(msg);
                prepareKeyShareEntry(msg);
                prepareEsniServerPublicKey(msg);
                prepareEsniRecordBytes(msg);
                prepareRecordDigest(msg);
                prepareRecordDigestLength(msg);
                prepareClientRandom(msg);
                prepareEsniContents(msg);
                prepareEsniContentsHash(msg);
                prepareEsniClientSharedSecret(msg);
                prepareEsniMasterSecret(msg);
                prepareEsniKey(msg);
                prepareEsniIv(msg);
                prepareClientHelloKeyShare(msg);
                prepereEncryptedSni(msg);
                prepereEncryptedSniLength(msg);
                break;
            case SERVER:
                prepereServerNonce(msg);
                break;
            default:
                break;
        }
    }

    @Override
    public void afterPrepareExtensionContent() {
        if (this.esniPreparatorMode == EsniPreparatorMode.CLIENT) {
            LOGGER.debug("Afterpreparing EncryptedServerNameIndicationExtension");
            prepareClientRandom(msg);
            prepareEsniContents(msg);
            prepareEsniContentsHash(msg);
            prepareEsniClientSharedSecret(msg);
            prepareEsniMasterSecret(msg);
            prepareEsniKey(msg);
            prepareEsniIv(msg);
            prepareClientHelloKeyShare(msg);
            prepereEncryptedSni(msg);
            prepereEncryptedSniLength(msg);
        }
    }

    public void prepareAfterParse() {
        if (this.esniPreparatorMode == EsniPreparatorMode.SERVER) {
            try {
                prepareClientRandom(msg);
                prepareEsniContents(msg);
                prepareEsniContentsHash(msg);
                prepareEsniServerSharedSecret(msg);
                prepareEsniMasterSecret(msg);
                prepareEsniKey(msg);
                prepareEsniIv(msg);
                prepareClientHelloKeyShare(msg);
                paresEncryptedSni(msg);
                parseClientEsniInnerBytes(msg);
            } catch (NullPointerException e) {
                throw new PreparationException(
                        "Missing parameters to prepareAfterParse EncryptedServerNameIndicationExtension", e);
            }
        }
    }

    private void prepareClientEsniInner(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInnerPreparator clientEsniInnerPreparator = new ClientEsniInnerPreparator(this.chooser,
                msg.getClientEsniInner());
        clientEsniInnerPreparator.prepare();
        ClientEsniInnerSerializer serializer = new ClientEsniInnerSerializer(msg.getClientEsniInner());
        try {
            this.streamClientEsniInnerBytes.write(serializer.serialize());
        } catch (IOException e) {
            e.printStackTrace();
            throw new PreparationException("Could not write byte[] from elientEsniInner", e);
        }
        msg.setClientEsniInnerBytes(streamClientEsniInnerBytes.toByteArray());
    }

    private void prepareClientEsniInnerBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setClientEsniInnerBytes(streamClientEsniInnerBytes.toByteArray());
        LOGGER.debug("clientEsniInnerBytes: "
                + ArrayConverter.bytesToHexString(msg.getClientEsniInnerBytes().getValue()));
    }

    private void parseClientEsniInnerBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInnerParser parser = new ClientEsniInnerParser(0, msg.getClientEsniInnerBytes().getValue());
        ClientEsniInner clientEsniInner = parser.parse();
        msg.setClientEsniInner(clientEsniInner);
    }

    private void prepareEsniServerPublicKey(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] serverPublicKey = chooser.getEsniServerKeyShareEntries().get(0).getPublicKey();
        for (KeyShareStoreEntry entry : chooser.getEsniServerKeyShareEntries()) {
            if (Arrays.equals(entry.getGroup().getValue(), msg.getKeyShareEntry().getGroup().getValue())) {
                serverPublicKey = entry.getPublicKey();
                break;
            }
        }
        msg.getEncryptedSniComputation().setEsniServerPublicKey(serverPublicKey);
        LOGGER.debug("esniServerPublicKey: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniServerPublicKey().getValue()));
    }

    private void prepareNamedGroup(EncryptedServerNameIndicationExtensionMessage msg) {
        List<NamedGroup> clientSupportedNamedGroups = chooser.getConfig().getClientSupportedEsniNamedGroups();
        List<NamedGroup> serverSupportedNamedGroups = new LinkedList();
        for (KeyShareStoreEntry entry : chooser.getEsniServerKeyShareEntries())
            serverSupportedNamedGroups.add(entry.getGroup());
        NamedGroup selectedNamedGroup;
        selectedNamedGroup = implementedNamedGroups.get(0);
        boolean isFoundSharedNamedGroup = false;
        for (NamedGroup g : clientSupportedNamedGroups) {
            if (implementedNamedGroups.contains(g)) {
                selectedNamedGroup = g;
                if (serverSupportedNamedGroups.contains(g)) {
                    isFoundSharedNamedGroup = true;
                    break;
                }
            }
        }
        if (!isFoundSharedNamedGroup)
            LOGGER.warn("Found no shared named group. Using " + selectedNamedGroup);

        msg.getKeyShareEntry().setGroupConfig(selectedNamedGroup);
        LOGGER.debug("NamedGroup: "
                + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getGroupConfig().getValue()));

    }

    private void prepareKeyShareEntry(EncryptedServerNameIndicationExtensionMessage msg) {
        KeyShareEntry keyShareEntry = msg.getKeyShareEntry();
        KeyShareEntryPreparator keyShareEntryPreparator = new KeyShareEntryPreparator(chooser, keyShareEntry);
        keyShareEntryPreparator.prepare();
        LOGGER.debug("ClientPrivateKey: "
                + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPrivateKey().toByteArray()));
        LOGGER.debug("ClientPublicKey: "
                + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPublicKey().getValue()));
    }

    private void prepareCipherSuite(EncryptedServerNameIndicationExtensionMessage msg) {
        List<CipherSuite> clientSupportedCiphersuites = chooser.getConfig().getClientSupportedEsniCiphersuites();
        List<CipherSuite> serverSupportedCiphersuites = ((DefaultChooser) chooser).getEsniServerCiphersuites();
        CipherSuite selectedCiphersuite = implementedCiphersuites.get(0);
        boolean isFoundSharedCipher = false;
        for (CipherSuite c : clientSupportedCiphersuites) {
            if (implementedCiphersuites.contains(c)) {
                selectedCiphersuite = c;
                if (serverSupportedCiphersuites.contains(c)) {
                    isFoundSharedCipher = true;
                    break;
                }
            }
        }
        if (!isFoundSharedCipher)
            LOGGER.warn("Found no shared cipher. Using " + selectedCiphersuite);

        msg.setCipherSuite(selectedCiphersuite.getByteValue());
        LOGGER.debug("CipherSuite: " + ArrayConverter.bytesToHexString(msg.getCipherSuite().getValue()));
    }

    private void prepareEsniRecordBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] recordBytes = chooser.getEsniRecordBytes();
        msg.getEncryptedSniComputation().setEsniRecordBytes(recordBytes);
        LOGGER.debug("esniRecordBytes: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniRecordBytes()));
    }

    private void prepareRecordDigest(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] recordDigest = null;
        byte[] record = msg.getEncryptedSniComputation().getEsniRecordBytes().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, cipherSuite);
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm.getJavaName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new PreparationException("Could not prepare recordDigest", e);
        }
        recordDigest = messageDigest.digest(record);
        msg.setRecordDigest(recordDigest);
        LOGGER.debug("RecordDigest: " + ArrayConverter.bytesToHexString(msg.getRecordDigest().getValue()));
    }

    private void prepareRecordDigestLength(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setRecordDigestLength(msg.getRecordDigest().getValue().length);
        LOGGER.debug("RecordDigestLength: " + msg.getRecordDigestLength().getValue());
    }

    private void prepareClientRandom(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] clienRandom = chooser.getClientRandom();
        if (clientHelloMessage != null)
            clienRandom = clientHelloMessage.getRandom().getValue();
        else
            clienRandom = chooser.getClientRandom();
        msg.getEncryptedSniComputation().setClientHelloRandom(clienRandom);
        LOGGER.debug("ClientHello: " + ArrayConverter.bytesToHexString(clienRandom));
    }

    private void prepareEsniContents(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] contents = generateEsniContents(msg);
        msg.getEncryptedSniComputation().setEsniContents(contents);
        LOGGER.debug("EsniContents: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniContents().getValue()));
    }

    private void prepareEsniContentsHash(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] contentsHash = null;
        byte[] contents = msg.getEncryptedSniComputation().getEsniContents().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, cipherSuite);
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm.getJavaName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new PreparationException("Could not prepare esniContentsHash", e);
        }
        contentsHash = messageDigest.digest(contents);
        msg.getEncryptedSniComputation().setEsniContentsHash(contentsHash);
        LOGGER.debug("EsniContentsHash: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniContentsHash().getValue()));
    }

    private void prepareEsniClientSharedSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        NamedGroup group = NamedGroup.getNamedGroup(msg.getKeyShareEntry().getGroup().getValue());
        BigInteger sk = msg.getKeyShareEntry().getPrivateKey();
        byte[] pk = msg.getEncryptedSniComputation().getEsniServerPublicKey().getValue();
        byte[] esniSharedSecret = computeSharedSecret(sk, pk, group);
        msg.getEncryptedSniComputation().setEsniSharedSecret(esniSharedSecret);
        LOGGER.debug("esniSharedSecret: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniSharedSecret().getValue()));
    }

    private void prepareEsniServerSharedSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        NamedGroup group = NamedGroup.getNamedGroup(msg.getKeyShareEntry().getGroup().getValue());
        boolean isFoundSharedNamedGroup = false;
        BigInteger serverPrivateKey = chooser.getConfig().getEsniServerKeyPairs().get(0).getPrivateKey();
        for (KeyShareEntry k : chooser.getConfig().getEsniServerKeyPairs()) {
            if (Arrays.equals(k.getGroup().getValue(), group.getValue())) {
                serverPrivateKey = k.getPrivateKey();
                isFoundSharedNamedGroup = true;
                break;
            }
        }
        if (!isFoundSharedNamedGroup) {
            LOGGER.warn("No private key available for selected named group: " + group);
        }
        byte[] pk = msg.getKeyShareEntry().getPublicKey().getValue();
        byte[] esniSharedSecret = computeSharedSecret(serverPrivateKey, pk, group);
        msg.getEncryptedSniComputation().setEsniSharedSecret(esniSharedSecret);
        LOGGER.debug("esniSharedSecret: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniSharedSecret().getValue()));
    }

    private void prepareEsniMasterSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] esniMasterSecret = null;
        byte[] esniSharedSecret = msg.getEncryptedSniComputation().getEsniSharedSecret().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        try {
            esniMasterSecret = HKDFunction.extract(hkdfAlgortihm, null, esniSharedSecret);
        } catch (CryptoException e) {
            e.printStackTrace();
            throw new PreparationException("Could not prepare esniMasterSecret", e);

        }
        msg.getEncryptedSniComputation().setEsniMasterSecret(esniMasterSecret);
        LOGGER.debug("esniMasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniMasterSecret().getValue()));
    }

    private void prepareEsniKey(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] key = null;
        byte[] esniMasterSecret = msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] hashIn = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        int keyLen = AlgorithmResolver.getCipher(cipherSuite).getKeySize();
        try {
            key = HKDFunction.expandLabel(hkdfAlgortihm, esniMasterSecret, HKDFunction.ESNI_KEY, hashIn, keyLen);
        } catch (CryptoException e) {
            e.printStackTrace();
            throw new PreparationException("Could not prepare esniKey", e);
        }
        msg.getEncryptedSniComputation().setEsniKey(key);
        LOGGER.debug("esniKey: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniKey().getValue()));
    }

    private void prepareEsniIv(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] iv = null;
        byte[] esniMasterSecret = msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] hashIn = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        int ivLen = AEAD_IV_LENGTH;
        try {
            iv = HKDFunction.expandLabel(hkdfAlgortihm, esniMasterSecret, HKDFunction.ESNI_IV, hashIn, ivLen);
        } catch (CryptoException e) {
            e.printStackTrace();
            throw new PreparationException("Could not prepare esniIv", e);
        }
        msg.getEncryptedSniComputation().setEsniIv(iv);
        LOGGER.debug("esniIv: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniIv().getValue()));
    }

    private void prepareClientHelloKeyShare(EncryptedServerNameIndicationExtensionMessage msg) {
        ByteArrayOutputStream clientKeyShareStream = new ByteArrayOutputStream();
        ByteArrayOutputStream clientHelloKeyShareStream = new ByteArrayOutputStream();

        for (KeyShareStoreEntry pair : chooser.getClientKeyShares()) {
            KeyShareEntry entry = new KeyShareEntry();
            KeyShareEntrySerializer serializer = new KeyShareEntrySerializer(entry);
            entry.setGroup(pair.getGroup().getValue());
            entry.setPublicKeyLength(pair.getPublicKey().length);
            entry.setPublicKey(pair.getPublicKey());
            try {
                clientKeyShareStream.write(serializer.serialize());
            } catch (IOException e) {
                e.printStackTrace();
                throw new PreparationException("Failed to write esniContents", e);
            }
        }
        byte[] keyShareListBytes = clientKeyShareStream.toByteArray();
        int keyShareListBytesLength = keyShareListBytes.length;
        byte[] keyShareListBytesLengthFild = ArrayConverter.intToBytes(keyShareListBytesLength,
                ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
        try {
            clientHelloKeyShareStream.write(keyShareListBytesLengthFild);
            clientHelloKeyShareStream.write(keyShareListBytes);
        } catch (IOException e) {
            e.printStackTrace();
            throw new PreparationException("Failed to write esniContents", e);
        }

        byte[] clientHelloKeyShareBytes = clientHelloKeyShareStream.toByteArray();
        msg.getEncryptedSniComputation().setClientHelloKeyShare(clientHelloKeyShareBytes);
        LOGGER.debug("clientHelloKeyShare: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue()));
    }

    private void prepereEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] encryptedSni = null;

        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        byte[] plainText = msg.getClientEsniInnerBytes().getValue();
        byte[] key = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] iv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] aad = msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        int tagBitLength;
        if (cipherSuite.isCCM_8()) {
            tagBitLength = AEAD_CCM_8_TAG_LENGTH * 8;
        } else {
            tagBitLength = AEAD_TAG_LENGTH * 8;
        }
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(key);
        EncryptionCipher encryptCipher = CipherWrapper.getEncryptionCipher(cipherSuite, ConnectionEndType.CLIENT,
                keySet);
        try {
            encryptedSni = encryptCipher.encrypt(iv, tagBitLength, aad, plainText);
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        msg.setEncryptedSni(encryptedSni);
        LOGGER.debug("EncryptedSni: " + ArrayConverter.bytesToHexString(msg.getEncryptedSni().getValue()));
    }

    private void paresEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] clientEsniInnerBytes = null;

        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        byte[] cipherText = msg.getEncryptedSni().getValue();
        byte[] key = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] iv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] aad = msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        int tagBitLength;
        if (cipherSuite.isCCM_8()) {
            tagBitLength = AEAD_CCM_8_TAG_LENGTH * 8;
        } else {
            tagBitLength = AEAD_TAG_LENGTH * 8;
        }
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(key);

        DecryptionCipher decryptCipher = CipherWrapper.getDecryptionCipher(cipherSuite, ConnectionEndType.SERVER,
                keySet);
        try {
            clientEsniInnerBytes = decryptCipher.decrypt(iv, tagBitLength, aad, cipherText);
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        msg.setClientEsniInnerBytes(clientEsniInnerBytes);
        LOGGER.debug("ClientesniInnerBytes: "
                + ArrayConverter.bytesToHexString(msg.getClientEsniInnerBytes().getValue()));
    }

    private void prepereEncryptedSniLength(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setEncryptedSniLength(msg.getEncryptedSni().getValue().length);
        LOGGER.debug("EncryptedSniLength: " + msg.getEncryptedSniLength().getValue());
    }

    private void prepereServerNonce(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] receivedClientNonce = chooser.getEsniClientNonce();
        msg.setServerNonce(receivedClientNonce);
        LOGGER.debug("ServerNonce: " + msg.getServerNonce().getValue());
    }

    private byte[] generateEsniContents(EncryptedServerNameIndicationExtensionMessage msg) {
        ByteArrayOutputStream contentsStream = new ByteArrayOutputStream();
        try {
            contentsStream.write(msg.getRecordDigestLength().getByteArray(ExtensionByteLength.RECORD_DIGEST_LENGTH));
            contentsStream.write(msg.getRecordDigest().getValue());
            contentsStream.write(msg.getKeyShareEntry().getGroup().getValue());
            contentsStream.write(msg.getKeyShareEntry().getPublicKeyLength()
                    .getByteArray(ExtensionByteLength.KEY_SHARE_LENGTH));
            contentsStream.write(msg.getKeyShareEntry().getPublicKey().getValue());
            contentsStream.write(msg.getEncryptedSniComputation().getClientHelloRandom().getValue());
        } catch (IOException e) {
            e.printStackTrace();
            throw new PreparationException("Failed to generate esniContents", e);
        }
        return contentsStream.toByteArray();
    }

    private byte[] computeSharedSecret(BigInteger privateKey, byte[] publicKey, NamedGroup group) {
        switch (group) {
            case ECDH_X25519:
                return ForgivingX25519Curve.computeSharedSecret(privateKey, publicKey);
            case ECDH_X448:
                return ForgivingX448Curve.computeSharedSecret(privateKey, publicKey);
            case SECP256R1:
                EllipticCurve curve = CurveFactory.getCurve(group);
                Point publicKeyPoint = PointFormatter.formatFromByteArray(group, publicKey);
                Point sharedPoint = curve.mult(privateKey, publicKeyPoint);
                int elementLenght = ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length;
                return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getX().getData(), elementLenght);
            default:
                throw new UnsupportedOperationException(group + " is unsupported");
        }
    }

    public EsniPreparatorMode getEsniPreparatorMode() {
        return esniPreparatorMode;
    }

    public void setEsniPreparatorMode(EsniPreparatorMode esniPreparatorMode) {
        this.esniPreparatorMode = esniPreparatorMode;
    }

}