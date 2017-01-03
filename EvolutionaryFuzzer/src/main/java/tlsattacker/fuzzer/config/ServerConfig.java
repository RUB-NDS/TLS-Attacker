/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.beust.jcommander.validators.PositiveInteger;

/**
 * A configuration class which configures the options for the "new-server"
 * command.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@Parameters(commandDescription = "Generates a new Server Config file")
public class ServerConfig {

    /**
     * The IP that should be put in the server config file
     */
    @Parameter(names = "-ip", required = false, description = "IP of the Server")
    private String ip = "127.0.0.1";

    /**
     * The port that should be put in the server config file
     */
    @Parameter(names = "-port", required = false, description = "Port of the Server", validateWith = PositiveInteger.class)
    private int port = 4433;

    /**
     * The String the fuzzer should wait for in the server output that should be
     * put in the server config file
     */
    @Parameter(names = "-accept", required = true, description = "The String the Server outputs when it finished booting")
    private String accept;

    /**
     * The command the fuzzer should use to start the server that should be put
     * in the server config file
     */
    @Parameter(names = "-start", required = true, description = "The command with which the Server is started. Can use placeholders:\n\t\t[cert] certificate used by the Server\n\t\t[key] private key used by the Server\n\t\t[port] port used by the Server")
    private String startcommand;

    /**
     * The Path to which the server config should be serialized to
     */
    @Parameter(names = "-output", required = true, description = "The File in which the Server is serialized to")
    private String output;

    /**
     * The command that should be used to kill the server that should be put in
     * the server config file
     */
    @Parameter(names = "-killCommand", required = false, description = "The Command needed to kill the Server after each execution, probably makes only sense in a single Threaded enviroment")
    private String killCommand;

    /**
     * The mayor Version of the TLS Server
     */
    @Parameter(names = "-mayor", required = false, description = "The mayor Version of the TLS Server")
    private String mayorVersion = "";

    /**
     * The minor Version of the TLS Server
     */
    @Parameter(names = "-minor", required = false, description = "The minor Version of the TLS Server")
    private String minorVersion = "";

    public String getMayorVersion() {
        return mayorVersion;
    }

    public void setMayorVersion(String mayorVersion) {
        this.mayorVersion = mayorVersion;
    }

    public String getMinorVersion() {
        return minorVersion;
    }

    public void setMinorVersion(String minorVersion) {
        this.minorVersion = minorVersion;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getKillCommand() {
        return killCommand;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getAccept() {
        return accept;
    }

    public void setAccept(String accept) {
        this.accept = accept;
    }

    public String getStartcommand() {
        return startcommand;
    }

    public void setStartcommand(String startcommand) {
        this.startcommand = startcommand;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

}
