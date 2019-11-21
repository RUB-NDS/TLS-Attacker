/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WorkflowTraceUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ProtocolMessage getFirstReceivedMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstReceivedMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static HandshakeMessage getLastReceivedMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastReceivedMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static AbstractRecord getLastReceivedRecord(WorkflowTrace trace) {
        List<AbstractRecord> recordList = getAllReceivedRecords(trace);
        if (recordList.isEmpty()) {
            return null;
        } else {
            return recordList.get(recordList.size() - 1);
        }
    }

    public static ProtocolMessage getFirstSendMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static ExtensionMessage getFirstSendExtension(ExtensionType type, WorkflowTrace trace) {
        List<ExtensionMessage> extensionList = getAllSendExtensions(trace);
        extensionList = filterExtensionList(extensionList, type);
        if (extensionList.isEmpty()) {
            return null;
        } else {
            return extensionList.get(0);
        }
    }

    public static List<HandshakeMessage> getAllSendHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllSendMessages(trace));
    }

    public static List<HandshakeMessage> getAllReceivedHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllReceivedMessages(trace));
    }

    public static List<ExtensionMessage> getAllSendExtensions(WorkflowTrace trace) {
        List<HandshakeMessage> handshakeMessageList = getAllSendHandshakeMessages(trace);
        List<ExtensionMessage> extensionList = new LinkedList<>();
        for (HandshakeMessage message : handshakeMessageList) {
            extensionList.addAll(message.getExtensions());
        }
        return extensionList;
    }

    public static List<ExtensionMessage> getAllReceivedExtensions(WorkflowTrace trace) {
        List<HandshakeMessage> handshakeMessageList = getAllReceivedHandshakeMessages(trace);
        List<ExtensionMessage> extensionList = new LinkedList<>();
        for (HandshakeMessage message : handshakeMessageList) {
            extensionList.addAll(message.getExtensions());
        }
        return extensionList;
    }

    public static HandshakeMessage getFirstSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static HandshakeMessage getLastSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastSendMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static boolean didReceiveMessage(ProtocolMessageType type, WorkflowTrace trace) {
        return getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didReceiveMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didSendMessage(ProtocolMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    public static boolean didSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    public static ProtocolMessage getLastReceivedMessage(WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    private static List<ProtocolMessage> filterMessageList(List<ProtocolMessage> messages, ProtocolMessageType type) {
        List<ProtocolMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage.getProtocolMessageType() == type) {
                returnedMessages.add(protocolMessage);
            }
        }
        return returnedMessages;
    }

    private static List<ExtensionMessage> filterExtensionList(List<ExtensionMessage> extensions, ExtensionType type) {
        List<ExtensionMessage> resultList = new LinkedList<>();
        for (ExtensionMessage extension : extensions) {
            if (extension.getExtensionTypeConstant() == type) {
                resultList.add(extension);
            }
        }
        return resultList;
    }

    public static List<HandshakeMessage> filterHandshakeMessagesFromList(List<ProtocolMessage> messages) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage.isHandshakeMessage()) {
                returnedMessages.add((HandshakeMessage) protocolMessage);
            }
        }
        return returnedMessages;
    }

    private static List<HandshakeMessage> filterMessageList(List<HandshakeMessage> messages, HandshakeMessageType type) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (HandshakeMessage handshakeMessage : messages) {
            if (handshakeMessage.getHandshakeMessageType() == type) {
                returnedMessages.add(handshakeMessage);
            }
        }
        return returnedMessages;
    }

    public static List<ProtocolMessage> getAllReceivedMessages(WorkflowTrace trace) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedMessages() != null) {
                receivedMessage.addAll(action.getReceivedMessages());
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllReceivedMessages(WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ProtocolMessage message : getAllReceivedMessages(trace)) {
            if (message.getProtocolMessageType() == type) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllSendMessages(WorkflowTrace trace) {
        List<ProtocolMessage> sendMessages = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendMessages.addAll(action.getSendMessages());
        }
        return sendMessages;
    }

    public static Boolean didReceiveTypeBeforeType(ProtocolMessageType protocolMessageType, HandshakeMessageType type,
            WorkflowTrace trace) {
        List<ProtocolMessage> receivedMessages = getAllReceivedMessages(trace);
        for (ProtocolMessage message : receivedMessages) {
            if (message.getProtocolMessageType() == protocolMessageType) {
                return true;
            }
            if (message instanceof HandshakeMessage) {
                if (((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    return false;
                }
            }
        }
        return false;
    }

    public static List<AbstractRecord> getAllReceivedRecords(WorkflowTrace trace) {
        List<AbstractRecord> receivedRecords = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            receivedRecords.addAll(action.getReceivedRecords());
        }
        return receivedRecords;
    }

    public static List<AbstractRecord> getAllSendRecords(WorkflowTrace trace) {
        List<AbstractRecord> sendRecords = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            if (action.getSendRecords() != null) {
                sendRecords.addAll(action.getSendRecords());
            }
        }
        return sendRecords;
    }

    public static SendingAction getLastSendingAction(WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();
        return sendingActions.get(sendingActions.size() - 1);
    }

    public WorkflowTraceUtil() {
    }

}
