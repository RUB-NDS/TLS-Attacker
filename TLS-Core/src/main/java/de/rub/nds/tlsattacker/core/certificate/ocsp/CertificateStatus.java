/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1EndOfContent;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.ContextRegister;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateInformationExtractor.asn1ToolInitialized;

// TODO: Find a way to share this variable

public class CertificateStatus {

    private final Logger LOGGER = LogManager.getLogger();
    private Asn1Sequence certStatusSequence;
    private String hashAlgorithmIdentifier;
    private byte[] issuerNameHash;
    private byte[] issuerKeyHash;
    private BigInteger serialNumber;
    private int certStatus;
    private String timeOfRevocation;
    private String timeOfLastUpdate;
    private String timeOfNextUpdate;

    public CertificateStatus(Asn1Sequence certStatusSequence) {
        // Init ASN.1 Tool
        if (!asn1ToolInitialized) {
            registerContexts();
            registerContentUnpackers();
            asn1ToolInitialized = true;
        }

        this.certStatusSequence = certStatusSequence;
        parseCertificateStatus(certStatusSequence);
    }

    private static void registerContexts() {
        ContextRegister contextRegister = ContextRegister.getInstance();
        contextRegister.registerContext(ParseNativeTypesContext.NAME, ParseNativeTypesContext.class);
        contextRegister.registerContext(ParseOcspTypesContext.NAME, ParseOcspTypesContext.class);
    }

    private static void registerContentUnpackers() {
        ContentUnpackerRegister contentUnpackerRegister = ContentUnpackerRegister.getInstance();
        contentUnpackerRegister.registerContentUnpacker(new DefaultContentUnpacker());
        contentUnpackerRegister.registerContentUnpacker(new PrimitiveBitStringUnpacker());
    }

    private void parseCertificateStatus(Asn1Sequence certStatusSeq) {
        Asn1Sequence requestInformation = (Asn1Sequence) certStatusSeq.getChildren().get(0);

        /*
         * At first, get information about the processed request. This MAY
         * differ from the original request sometimes, as some responders don't
         * need all values to match to give a response for a given certificate.
         * DigiCert's OCSP responder, for example, also accepts an invalid
         * issuerKeyHash in a request if the other values match up and returns
         * the correct one in the response.
         */

        Asn1Sequence hashAlgorithmSequence = (Asn1Sequence) requestInformation.getChildren().get(0);
        hashAlgorithmIdentifier = ((Asn1ObjectIdentifier) hashAlgorithmSequence.getChildren().get(0)).getValue();

        // Workaround for ASN.1 Tool messing up the correct type occasionally,
        // switching between Primitive and Encapsulated
        Asn1Encodable issuerNameHashObject = requestInformation.getChildren().get(1);
        Asn1Encodable issuerKeyHashObject = requestInformation.getChildren().get(2);
        if (issuerNameHashObject instanceof Asn1PrimitiveOctetString) {
            issuerNameHash = ((Asn1PrimitiveOctetString) issuerNameHashObject).getValue();
        } else if (issuerNameHashObject instanceof Asn1EncapsulatingOctetString) {
            issuerNameHash = ((Asn1EncapsulatingOctetString) issuerNameHashObject).getContent().getOriginalValue();
        }
        if (issuerKeyHashObject instanceof Asn1PrimitiveOctetString) {
            issuerKeyHash = ((Asn1PrimitiveOctetString) issuerKeyHashObject).getValue();
        } else if (issuerKeyHashObject instanceof Asn1EncapsulatingOctetString) {
            issuerKeyHash = ((Asn1EncapsulatingOctetString) issuerKeyHashObject).getContent().getOriginalValue();
        }

        serialNumber = ((Asn1Integer) requestInformation.getChildren().get(3)).getValue();

        /*
         * And here comes the revocation status. ASN.1 Tool is buggy and gets
         * sometimes Null or EndOfContent for a 'good' status, so we treat them
         * both as good status.
         */

        Asn1Encodable certStatusObject = certStatusSeq.getChildren().get(1);

        // Good status
        if (certStatusObject instanceof Asn1Null || certStatusObject instanceof Asn1EndOfContent) {
            certStatus = 0; // good, not revoked
        }

        // Time of next update (offset 0), revoked (offset 1) or unknown
        // (offset 2) status
        else if (certStatusObject instanceof Asn1Explicit) {
            Asn1Explicit certStatusExplicitObject = (Asn1Explicit) certStatusObject;
            switch (certStatusExplicitObject.getOffset()) {
                case 1:
                    certStatus = 1; // revoked
                    timeOfRevocation = ((Asn1PrimitiveGeneralizedTime) certStatusExplicitObject.getChildren().get(0))
                            .getValue();
                    break;
                case 2:
                    certStatus = 2; // unknown
                    break;
            }
        }

        // After the status comes the mandatory timeOfLastUpdate
        Asn1PrimitiveGeneralizedTime timeOfLastUpdateObject = (Asn1PrimitiveGeneralizedTime) certStatusSeq
                .getChildren().get(2);
        timeOfLastUpdate = timeOfLastUpdateObject.getValue();

        // And at last, optional tags for lastUpdate and extensions
        for (int i = 3; i < certStatusSeq.getChildren().size(); i++) {
            Asn1Encodable nextObject = certStatusSeq.getChildren().get(i);
            if (nextObject instanceof Asn1Explicit) {
                Asn1Explicit nextExplicitObject = (Asn1Explicit) nextObject;

                switch (nextExplicitObject.getOffset()) {
                    case 0:
                        timeOfNextUpdate = ((Asn1PrimitiveGeneralizedTime) nextExplicitObject.getChildren().get(0))
                                .getValue();
                        break;
                    case 1:
                        // TODO: Add support for singleExtensions here.
                        break;
                }
            }
        }
    }
}
