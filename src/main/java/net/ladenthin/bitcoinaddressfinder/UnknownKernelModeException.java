package net.ladenthin.bitcoinaddressfinder;

import net.ladenthin.bitcoinaddressfinder.configuration.CProducer;

/**
 * This exception will be thrown when an unknown kernel mode defined in the configuration class {@link CProducer} is set for the OpenCL context.
 */
public class UnknownKernelModeException extends Throwable {
    public UnknownKernelModeException(int kernelMode) {
        super("Unknown kernelMode \"" + kernelMode + "\"!");
    }
}