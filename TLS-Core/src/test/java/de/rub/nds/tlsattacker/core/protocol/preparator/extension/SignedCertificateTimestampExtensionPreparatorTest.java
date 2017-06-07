/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignedCertificateTimestampExtensionHandlerTest;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SignedCertificateTimestampExtensionPreparatorTest {

    private final ExtensionType extensionType;
    private final int lengthFirstPackage;
    private final byte[] firstTimestamp;
    private final byte[] firstExpectedBytes;
    private final byte[] secondTimestamp;
    private final byte[] secondExpectedBytes;
    private final int lengthSecondPackage;
    private final int startPosition;
    private TlsContext context;
    private SignedCertificateTimestampExtensionMessage message;
    private SignedCertificateTimestampExtensionPreparator preparator;

    public SignedCertificateTimestampExtensionPreparatorTest(ExtensionType extensionType, int lengthFirstPackage,
            byte[] firstTimestamp, byte[] firstExpectedBytes, byte[] secondTimestamp, byte[] secondExpectedBytes,
            int lengthSecondPackage, int startPosition) {
        this.extensionType = extensionType;
        this.lengthFirstPackage = lengthFirstPackage;
        this.firstTimestamp = firstTimestamp;
        this.firstExpectedBytes = firstExpectedBytes;
        this.secondTimestamp = secondTimestamp;
        this.secondExpectedBytes = secondExpectedBytes;
        this.lengthSecondPackage = lengthSecondPackage;
        this.startPosition = startPosition;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SignedCertificateTimestampExtensionHandlerTest.generateData();
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new SignedCertificateTimestampExtensionMessage();
        preparator = new SignedCertificateTimestampExtensionPreparator(context,
                (SignedCertificateTimestampExtensionMessage) message);
    }

    @Test
    public void testPreparator() {
        context.getConfig().setSignedCertificateTimestamp(secondTimestamp);
        preparator.prepare();

        assertEquals(lengthSecondPackage, (int) message.getExtensionLength().getValue());
        assertArrayEquals(secondTimestamp, message.getSignedTimestamp().getValue());
    }
}
