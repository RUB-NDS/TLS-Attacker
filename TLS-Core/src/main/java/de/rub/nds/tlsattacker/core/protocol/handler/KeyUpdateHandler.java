/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.KeyUpdateRequest;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.KeyUpdateParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.KeyUpdatePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.KeyUpdateSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdateHandler extends HandshakeMessageHandler<KeyUpdateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyUpdateHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(KeyUpdateMessage message) {

    }

    @Override
    public void adjustTlsContextAfterSerialize(KeyUpdateMessage message) {

        if (message.getRequestUpdate() == KeyUpdateRequest.UPDATE_REQUESTED) {
            adjustApplicationTrafficSecrets();
        }
        setRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);

    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {

        return new KeyUpdateParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
                tlsContext.getConfig());

    }

    @Override
    public ProtocolMessagePreparator getPreparator(KeyUpdateMessage message) {
        if (tlsContext.getChooser().getTalkingConnectionEnd() != tlsContext.getChooser().getConnectionEndType()) {
            if (message.getRequestUpdate() == KeyUpdateRequest.UPDATE_REQUESTED) {
                adjustApplicationTrafficSecrets();
            }
            setRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
        }
        return new KeyUpdatePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ProtocolMessageSerializer getSerializer(KeyUpdateMessage message) {
        return new KeyUpdateSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser()
                .getSelectedCipherSuite());

        try {

            Mac mac = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName());
            byte[] clientApplicationTrafficSecret = HKDFunction.expandLabel(hkdfAlgortihm,
                    tlsContext.getClientApplicationTrafficSecret(), HKDFunction.TRAFFICUPD, new byte[0],
                    mac.getMacLength());

            tlsContext.setClientApplicationTrafficSecret(clientApplicationTrafficSecret);
            LOGGER.debug("Set clientApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));

            byte[] serverApplicationTrafficSecret = HKDFunction.expandLabel(hkdfAlgortihm,
                    tlsContext.getServerApplicationTrafficSecret(), HKDFunction.TRAFFICUPD, new byte[0],
                    mac.getMacLength());

            tlsContext.setServerApplicationTrafficSecret(serverApplicationTrafficSecret);
            LOGGER.debug("Set serverApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));

        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new AdjustmentException(ex);
        }
    }

    private KeySet getKeySet(TlsContext context, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            KeySet keySet = KeySetGenerator.generateKeySet(context, context.getChooser().getSelectedProtocolVersion(),
                    keySetType);

            return keySet;
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    private void setRecordCipher(Tls13KeySetType keySetType) {
        try {
            int AEAD_IV_LENGTH = 12;
            HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser()
                    .getSelectedCipherSuite());

            tlsContext.setActiveClientKeySetType(keySetType);
            LOGGER.debug("Setting cipher for client to use " + keySetType);
            KeySet keySet = getKeySet(tlsContext, tlsContext.getActiveClientKeySetType());

            if (tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.CLIENT
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                    || tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.SERVER
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {

                if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
                    keySet.setClientWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getClientApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setClientWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getClientApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                            AlgorithmResolver.getCipher(tlsContext.getChooser().getSelectedCipherSuite()).getKeySize()));
                } else {

                    keySet.setServerWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getServerApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setServerWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getServerApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                            AlgorithmResolver.getCipher(tlsContext.getChooser().getSelectedCipherSuite()).getKeySize()));
                }

            } else if (tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.SERVER
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                    || tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.CLIENT
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {

                if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {

                    keySet.setServerWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getServerApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setServerWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getServerApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                            AlgorithmResolver.getCipher(tlsContext.getChooser().getSelectedCipherSuite()).getKeySize()));

                } else {

                    keySet.setClientWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getClientApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setClientWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                            tlsContext.getClientApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                            AlgorithmResolver.getCipher(tlsContext.getChooser().getSelectedCipherSuite()).getKeySize()));
                }

            }

            RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(tlsContext, keySet, tlsContext
                    .getChooser().getSelectedCipherSuite());
            tlsContext.getRecordLayer().setRecordCipher(recordCipherClient);

            if (tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.CLIENT
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                    || tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.SERVER
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {

                tlsContext.setWriteSequenceNumber(0);
                tlsContext.getRecordLayer().updateEncryptionCipher();
            } else if (tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.SERVER
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                    || tlsContext.getChooser().getTalkingConnectionEnd() == ConnectionEndType.CLIENT
                    && tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {

                tlsContext.setReadSequenceNumber(0);
                tlsContext.getRecordLayer().updateDecryptionCipher();
            }

        } catch (CryptoException ex) {
            throw new AdjustmentException(ex);
        }

    }
}
