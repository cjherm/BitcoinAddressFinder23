// @formatter:off
/**
 * Copyright 2020 Bernard Ladenthin bernard.ladenthin@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
// @formatter:on
package net.ladenthin.bitcoinaddressfinder;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducer;
import static org.jocl.CL.CL_MEM_READ_ONLY;
import static org.jocl.CL.CL_MEM_USE_HOST_PTR;
import static org.jocl.CL.CL_MEM_WRITE_ONLY;
import static org.jocl.CL.CL_TRUE;
import static org.jocl.CL.clCreateBuffer;
import static org.jocl.CL.clEnqueueNDRangeKernel;
import static org.jocl.CL.clEnqueueReadBuffer;
import static org.jocl.CL.clEnqueueWriteBuffer;
import static org.jocl.CL.clFinish;
import static org.jocl.CL.clReleaseMemObject;
import static org.jocl.CL.clSetKernelArg;
import org.jocl.Pointer;
import org.jocl.Sizeof;
import org.jocl.cl_command_queue;
import org.jocl.cl_context;
import org.jocl.cl_kernel;
import org.jocl.cl_mem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenClTask {

    protected Logger logger = LoggerFactory.getLogger(this.getClass());
    
    /**
     * I din't know which is better.
     */
    private static final boolean USE_HOST_PTR = false;

    private final CProducer cProducer;

    private final cl_context context;
    private final ByteBuffer srcByteBuffer;
    private final Pointer srcPointer;

    private final cl_mem srcMem;

    // Only available after init
    public OpenClTask(cl_context context, CProducer cProducer) {
        this.context = context;
        this.cProducer = cProducer;

        int srcSizeInBytes = getSrcSizeInBytes();
        srcByteBuffer = ByteBuffer.allocateDirect(srcSizeInBytes);
        srcPointer = Pointer.to(srcByteBuffer);
        srcMem = clCreateBuffer(
                context,
                CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                srcSizeInBytes,
                srcPointer,
                null
        );
    }

    public int getSrcSizeInBytes() {
        if (cProducer.chunkMode) {
            return PublicKeyBytes.PRIVATE_KEY_MAX_NUM_BYTES;
        } else {
            return PublicKeyBytes.PRIVATE_KEY_MAX_NUM_BYTES * cProducer.getWorkSize();
        }
    }

    public int getDstSizeInBytes() {
        if (cProducer.kernelMode == OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE) {
            return PublicKeyBytes.TWO_COORDINATES_NUM_BYTES * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE) {
            return ResultBytesFactory.NUM_BYTES_TOTAL_UNTIL_PUBLIC_KEY * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_RIPEMD160_ONLY_MODE) {
            return Ripemd160BytesFactory.NUM_BYTES_TOTAL * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_ADDRESSES_ONLY_MODE) {
            return AddressBytesFactory.NUM_BYTES_TOTAL * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE) {
            return ResultBytesFactory.NUM_BYTES_TOTAL_UNTIL_1ST_SHA256 * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_UNTIL_RIPEMD160_MODE) {
            return ResultBytesFactory.NUM_BYTES_TOTAL_UNTIL_RIPEMD160 * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE) {
            return ResultBytesFactory.NUM_BYTES_TOTAL_UNTIL_2ND_SHA256 * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE) {
            return ResultBytesFactory.NUM_BYTES_TOTAL_UNTIL_3RD_SHA256 * cProducer.getWorkSize();
        } else if (cProducer.kernelMode == OpenCLContext.GEN_UNTIL_ADDRESS_MODE) {
            return ResultBytesFactory.NUM_BYTES_TOTAL_UNTIL_ADDRESS * cProducer.getWorkSize();
        }
        return 0;
    }

    public void setSrcPrivateKeys(BigInteger[] privateKeys) throws InvalidWorkSizeException {

        int workSize = cProducer.getWorkSize();

        if (!cProducer.chunkMode && (privateKeys.length != workSize)) {
            throw new InvalidWorkSizeException("The number of private keys (actual = " + privateKeys.length + ") must be exactly the same as the work size: " + workSize + " when the chunk mode is deactivated!");
        } else if (cProducer.chunkMode && (privateKeys.length < 1)) {
            throw new InvalidWorkSizeException("At least 1 private key is necessary! (actual = " + privateKeys.length + ")");
        }

        byte[] privateKeyChunkAsByteArray = KeyUtility.bigIntegersToBytes(privateKeys);

        srcByteBuffer.clear();
        srcByteBuffer.put(privateKeyChunkAsByteArray, 0, privateKeyChunkAsByteArray.length);
    }

    
    public ByteBuffer executeKernel(cl_kernel kernel, cl_command_queue commandQueue) {
        // allocate a new dst buffer that a clone afterwards is not necessary
        final ByteBuffer dstByteBuffer = ByteBuffer.allocateDirect(getDstSizeInBytes());
        final Pointer dstPointer = Pointer.to(dstByteBuffer);
        final cl_mem dstMem;
        if (USE_HOST_PTR) {
            dstMem = clCreateBuffer(
                    context,
                    CL_MEM_USE_HOST_PTR,
                    getDstSizeInBytes(),
                    dstPointer,
                    null
            );
        } else {
            dstMem = clCreateBuffer(
                    context,
                    CL_MEM_WRITE_ONLY,
                    getDstSizeInBytes(),
                    null,
                    null
            );
        }

        // Set the arguments for the kernel
        clSetKernelArg(kernel, 0, Sizeof.cl_mem, Pointer.to(dstMem));
        clSetKernelArg(kernel, 1, Sizeof.cl_mem, Pointer.to(srcMem));

        // Set the work-item dimensions
        long global_work_size[] = new long[]{cProducer.getWorkSize()};
        long localWorkSize[] = null; // new long[]{1}; // enabling the system to choose the work-group size.
        int workDim = 1;

        {
            // write src buffer
            clEnqueueWriteBuffer(
                    commandQueue,
                    srcMem,
                    CL_TRUE,
                    0,
                    getSrcSizeInBytes(),
                    srcPointer,
                    0,
                    null,
                    null
            );
            clFinish(commandQueue);
        }
        {
            // execute the kernel
            long beforeExecute = System.currentTimeMillis();
            clEnqueueNDRangeKernel(
                    commandQueue,
                    kernel,
                    workDim,
                    null,
                    global_work_size,
                    localWorkSize,
                    0,
                    null,
                    null
            );
            clFinish(commandQueue);

            long afterExecute = System.currentTimeMillis();
            
            if (logger.isTraceEnabled()) {
                logger.trace("Executed OpenCL kernel in " + (afterExecute - beforeExecute) + "ms");
            }
        }
        {
            // read the dst buffer
            long beforeRead = System.currentTimeMillis();

            clEnqueueReadBuffer(
                    commandQueue,
                    dstMem,
                    CL_TRUE,
                    0,
                    getDstSizeInBytes(),
                    dstPointer,
                    0,
                    null,
                    null
            );
            clFinish(commandQueue);
            clReleaseMemObject(dstMem);

            long afterRead = System.currentTimeMillis();
            if (logger.isTraceEnabled()) {
                logger.trace("Read OpenCL data "+((getDstSizeInBytes() / 1024) / 1024) + "Mb in " + (afterRead - beforeRead) + "ms");
            }
        }
        return dstByteBuffer;
    }

    public void releaseCl() {
        clReleaseMemObject(srcMem);
    }

    /**
     * https://stackoverflow.com/questions/3366925/deep-copy-duplicate-of-javas-bytebuffer/4074089
     */
    private static ByteBuffer cloneByteBuffer(final ByteBuffer original) {
        // Create clone with same capacity as original.
        final ByteBuffer clone = (original.isDirect())
                ? ByteBuffer.allocateDirect(original.capacity())
                : ByteBuffer.allocate(original.capacity());

        // Create a read-only copy of the original.
        // This allows reading from the original without modifying it.
        final ByteBuffer readOnlyCopy = original.asReadOnlyBuffer();

        // Flip and read from the original.
        readOnlyCopy.flip();
        clone.put(readOnlyCopy);

        return clone;
    }
}
