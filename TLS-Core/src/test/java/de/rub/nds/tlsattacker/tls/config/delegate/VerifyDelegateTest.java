/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class VerifyDelegateTest {

    private VerifyDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public VerifyDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new VerifyDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isVerifyWorkflowCorrectness method, of class VerifyDelegate.
     */
    @Test
    public void testIsVerifyWorkflowCorrectness() {
        args = new String[1];
        args[0] = "-verify_workflow_correctness";
        assertFalse(delegate.isVerifyWorkflowCorrectness());
        jcommander.parse(args);
        assertTrue(delegate.isVerifyWorkflowCorrectness());
    }

    /**
     * Test of setVerifyWorkflowCorrectness method, of class VerifyDelegate.
     */
    @Test
    public void testSetVerifyWorkflowCorrectness() {
        assertFalse(delegate.isVerifyWorkflowCorrectness());
        delegate.setVerifyWorkflowCorrectness(true);
        assertTrue(delegate.isVerifyWorkflowCorrectness());
    }

    /**
     * Test of applyDelegate method, of class VerifyDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = new TlsConfig();
        args = new String[1];
        args[0] = "-verify_workflow_correctness";
        jcommander.parse(args);
        config.setVerifyWorkflow(false);
        assertFalse(config.isVerifyWorkflow());
        delegate.applyDelegate(config);
        assertTrue(config.isVerifyWorkflow());
    }
}