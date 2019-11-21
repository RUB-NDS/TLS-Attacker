/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum NamedGroup {

    SECT163K1(new byte[] { (byte) 0, (byte) 1 }, "sect163k1", 163),
    SECT163R1(new byte[] { (byte) 0, (byte) 2 }, "sect163r1", 163),
    SECT163R2(new byte[] { (byte) 0, (byte) 3 }, "sect163r2", 163),
    SECT193R1(new byte[] { (byte) 0, (byte) 4 }, "sect193r1", 193),
    SECT193R2(new byte[] { (byte) 0, (byte) 5 }, "sect193r2", 193),
    SECT233K1(new byte[] { (byte) 0, (byte) 6 }, "sect233k1", 233),
    SECT233R1(new byte[] { (byte) 0, (byte) 7 }, "sect233r1", 233),
    SECT239K1(new byte[] { (byte) 0, (byte) 8 }, "sect239k1", 239),
    SECT283K1(new byte[] { (byte) 0, (byte) 9 }, "sect283k1", 283),
    SECT283R1(new byte[] { (byte) 0, (byte) 10 }, "sect283r1", 283),
    SECT409K1(new byte[] { (byte) 0, (byte) 11 }, "sect409k1", 409),
    SECT409R1(new byte[] { (byte) 0, (byte) 12 }, "sect409r1", 409),
    SECT571K1(new byte[] { (byte) 0, (byte) 13 }, "sect571k1", 571),
    SECT571R1(new byte[] { (byte) 0, (byte) 14 }, "sect571r1", 571),
    SECP160K1(new byte[] { (byte) 0, (byte) 15 }, "secp160k1", 160),
    SECP160R1(new byte[] { (byte) 0, (byte) 16 }, "secp160r1", 160),
    SECP160R2(new byte[] { (byte) 0, (byte) 17 }, "secp160r2", 150),
    SECP192K1(new byte[] { (byte) 0, (byte) 18 }, "secp192k1", 192),
    SECP192R1(new byte[] { (byte) 0, (byte) 19 }, "secp192r1", 192),
    SECP224K1(new byte[] { (byte) 0, (byte) 20 }, "secp224k1", 224),
    SECP224R1(new byte[] { (byte) 0, (byte) 21 }, "secp224r1", 224),
    SECP256K1(new byte[] { (byte) 0, (byte) 22 }, "secp256k1", 256),
    SECP256R1(new byte[] { (byte) 0, (byte) 23 }, "secp256r1", 256),
    SECP384R1(new byte[] { (byte) 0, (byte) 24 }, "secp384r1", 384),
    SECP521R1(new byte[] { (byte) 0, (byte) 25 }, "secp521r1", 521),
    BRAINPOOLP256R1(new byte[] { (byte) 0, (byte) 26 }, "brainpoolp256r1", 256),
    BRAINPOOLP384R1(new byte[] { (byte) 0, (byte) 27 }, "brainpoolp384r1", 384),
    BRAINPOOLP512R1(new byte[] { (byte) 0, (byte) 28 }, "brainpoolp512r1", 512),
    ECDH_X25519(new byte[] { (byte) 0, (byte) 29 }, "ecdh_X25519", 256),
    ECDH_X448(new byte[] { (byte) 0, (byte) 30 }, "ecdh_X448", 448),
    FFDHE2048(new byte[] { (byte) 1, (byte) 0 }, "FFDHE2048", 2048),
    FFDHE3072(new byte[] { (byte) 1, (byte) 1 }, "FFDHE3072", 3072),
    FFDHE4096(new byte[] { (byte) 1, (byte) 2 }, "FFDHE4096", 4096),
    FFDHE6144(new byte[] { (byte) 1, (byte) 3 }, "FFDHE6144", 6144),
    FFDHE8192(new byte[] { (byte) 1, (byte) 4 }, "FFDHE8192", 8192),
    // GREASE constants
    GREASE_00(new byte[] { (byte) 0x0A, (byte) 0x0A }, "GREASE", null),
    GREASE_01(new byte[] { (byte) 0x1A, (byte) 0x1A }, "GREASE", null),
    GREASE_02(new byte[] { (byte) 0x2A, (byte) 0x2A }, "GREASE", null),
    GREASE_03(new byte[] { (byte) 0x3A, (byte) 0x3A }, "GREASE", null),
    GREASE_04(new byte[] { (byte) 0x4A, (byte) 0x4A }, "GREASE", null),
    GREASE_05(new byte[] { (byte) 0x5A, (byte) 0x5A }, "GREASE", null),
    GREASE_06(new byte[] { (byte) 0x6A, (byte) 0x6A }, "GREASE", null),
    GREASE_07(new byte[] { (byte) 0x7A, (byte) 0x7A }, "GREASE", null),
    GREASE_08(new byte[] { (byte) 0x8A, (byte) 0x8A }, "GREASE", null),
    GREASE_09(new byte[] { (byte) 0x9A, (byte) 0x9A }, "GREASE", null),
    GREASE_10(new byte[] { (byte) 0xAA, (byte) 0xAA }, "GREASE", null),
    GREASE_11(new byte[] { (byte) 0xBA, (byte) 0xBA }, "GREASE", null),
    GREASE_12(new byte[] { (byte) 0xCA, (byte) 0xCA }, "GREASE", null),
    GREASE_13(new byte[] { (byte) 0xDA, (byte) 0xDA }, "GREASE", null),
    GREASE_14(new byte[] { (byte) 0xEA, (byte) 0xEA }, "GREASE", null),
    GREASE_15(new byte[] { (byte) 0xFA, (byte) 0xFA }, "GREASE", null);

    private static final Logger LOGGER = LogManager.getLogger();

    public static final int LENGTH = 2;

    private byte[] value;

    private String javaName;

    private final Integer coordinateSizeInBit;

    private static final Map<Integer, NamedGroup> MAP;

    private static final Set<NamedGroup> tls13Groups = new HashSet<>(Arrays.asList(ECDH_X25519, ECDH_X448, FFDHE2048,
            FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192, SECP256R1, SECP384R1, SECP521R1));

    private NamedGroup(byte[] value, String javaName, Integer coordinateSizeInBit) {
        this.value = value;
        this.javaName = javaName;
        this.coordinateSizeInBit = coordinateSizeInBit;
    }

    static {
        MAP = new HashMap<>();
        for (NamedGroup c : NamedGroup.values()) {
            MAP.put(valueToInt(c.value), c);
        }
    }

    public static NamedGroup fromJavaName(String name) {
        if (name.equals("prime256v1")) {
            return SECP256R1;
        }
        for (NamedGroup group : values()) {
            if (group.getJavaName().equals(name)) {
                return group;
            }
        }
        return null;
    }

    public String getJavaName() {
        return javaName;
    }

    public void setJavaName(String javaName) {
        this.javaName = javaName;
    }

    private static Integer valueToInt(byte[] value) {
        if (value.length < 2) {
            LOGGER.warn("Could not convert NamedGroup. Returning null");
            return null;
        }
        return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public static NamedGroup getNamedGroup(byte[] value) {
        return MAP.get(valueToInt(value));
    }

    public static NamedGroup getNamedGroup(ECPublicKey publicKey) {
        for (NamedGroup group : getImplemented()) {
            // TODO: X25519 and X448 not supported for classic java curves
            if (group.isCurve() && group.isStandardCurve()) {
                try {
                    EllipticCurve tlsAttackerCurve = CurveFactory.getCurve(group);
                    if (publicKey.getParams().getGenerator().getAffineX()
                            .equals(tlsAttackerCurve.getBasePoint().getX().getData())
                            && publicKey.getParams().getGenerator().getAffineY()
                                    .equals(tlsAttackerCurve.getBasePoint().getY().getData())) {
                        return group;
                    }
                } catch (UnsupportedOperationException E) {
                    LOGGER.debug("Could not test " + group.name() + " not completly integrated");
                }
            }
        }
        return null;
    }

    public static NamedGroup getNamedGroup(ECPrivateKey privateKey) {
        for (NamedGroup group : getImplemented()) {
            // TODO: X25519 and X448 not supported for classic java curves
            if (group.isCurve() && group.isStandardCurve()) {
                try {
                    EllipticCurve tlsAttackerCurve = CurveFactory.getCurve(group);
                    if (privateKey.getParams().getGenerator().getAffineX()
                            .equals(tlsAttackerCurve.getBasePoint().getX().getData())
                            && privateKey.getParams().getGenerator().getAffineY()
                                    .equals(tlsAttackerCurve.getBasePoint().getY().getData())) {
                        return group;
                    }
                } catch (UnsupportedOperationException E) {
                    LOGGER.debug("Could not test " + group.name() + " not completly integrated");
                }
            }
        }
        return null;
    }

    public byte[] getValue() {
        return value;
    }

    public Integer getCoordinateSizeInBit() {
        return coordinateSizeInBit;
    }

    public static NamedGroup getRandom(Random random) {
        NamedGroup c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (NamedGroup) o[random.nextInt(o.length)];
        }
        return c;
    }

    public Integer getIntValue() {
        return valueToInt(value);
    }

    public static byte[] namedGroupsToByteArray(List<NamedGroup> groups) throws IOException {
        if (groups == null || groups.isEmpty()) {
            return new byte[0];
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(bytes);
        os.writeObject(groups.toArray(new NamedGroup[groups.size()]));

        return bytes.toByteArray();
    }

    public static NamedGroup[] namedGroupsFromByteArray(byte[] sourceBytes) throws IOException, ClassNotFoundException {
        if (sourceBytes == null || sourceBytes.length == 0) {
            return new NamedGroup[0];
        }

        if (sourceBytes.length % NamedGroup.LENGTH != 0) {
            throw new IllegalArgumentException("Failed to convert byte array. "
                    + "Source array size is not a multiple of destination type size.");
        }

        ByteArrayInputStream in = new ByteArrayInputStream(sourceBytes);
        ObjectInputStream is = new ObjectInputStream(in);
        NamedGroup[] groups = (NamedGroup[]) is.readObject();
        return groups;
    }

    public boolean isStandardCurve() {
        return this.isCurve() && this != ECDH_X25519 && this != ECDH_X448;

    }

    public boolean isCurve() {
        return this.name().toLowerCase().contains("ec") || this.name().toLowerCase().contains("brainpool");
    }

    public boolean isDhGroup() {
        return this.name().toLowerCase().contains("dhe");
    }

    public boolean isGrease() {
        return this.name().contains("GREASE");
    }

    public static List<NamedGroup> getImplemented() {
        List<NamedGroup> list = new LinkedList<>();
        list.add(SECP160K1);
        list.add(SECP160R1);
        list.add(SECP160R2);
        list.add(SECP192K1);
        list.add(SECP192R1);
        list.add(SECP224K1);
        list.add(SECP224R1);
        list.add(SECP256K1);
        list.add(SECP256R1);
        list.add(SECP384R1);
        list.add(SECP521R1);
        list.add(SECT163K1);
        list.add(SECT163R1);
        list.add(SECT163R2);
        list.add(SECT193R1);
        list.add(SECT193R2);
        list.add(SECT233K1);
        list.add(SECT233R1);
        list.add(SECT239K1);
        list.add(SECT283K1);
        list.add(SECT283R1);
        list.add(SECT409K1);
        list.add(SECT409R1);
        list.add(SECT571K1);
        list.add(SECT571R1);
//        list.add(ECDH_X25519);
//        list.add(ECDH_X448);
        list.add(BRAINPOOLP256R1);
        list.add(BRAINPOOLP384R1);
        list.add(BRAINPOOLP512R1);
        return list;
    }

    public boolean isTls13() {
        return tls13Groups.contains(this);
    }

    public boolean isGost() {
        return name().contains("GOST");
    }
}
