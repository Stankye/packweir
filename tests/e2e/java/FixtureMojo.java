package dev.packweir;

import org.apache.maven.plugin.AbstractMojo;

/** A test-owned plugin whose descriptor asks Maven core to resolve project dependencies. */
public final class FixtureMojo extends AbstractMojo {
    public void execute() {
        getLog().info("Packweir fixture dependencies resolved");
    }
}
