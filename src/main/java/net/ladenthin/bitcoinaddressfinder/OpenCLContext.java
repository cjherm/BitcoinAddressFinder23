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

import com.google.common.io.Resources;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;
import static org.jocl.CL.CL_CONTEXT_PLATFORM;
import static org.jocl.CL.clBuildProgram;
import static org.jocl.CL.clCreateCommandQueueWithProperties;
import static org.jocl.CL.clCreateContext;
import static org.jocl.CL.clCreateKernel;
import static org.jocl.CL.clCreateProgramWithSource;
import static org.jocl.CL.clGetDeviceIDs;
import static org.jocl.CL.clGetPlatformIDs;
import static org.jocl.CL.clReleaseCommandQueue;
import static org.jocl.CL.clReleaseContext;
import org.jocl.cl_command_queue;
import org.jocl.cl_context;
import org.jocl.cl_context_properties;
import org.jocl.cl_device_id;
import org.jocl.cl_kernel;
import org.jocl.cl_platform_id;
import org.jocl.cl_program;
import org.jocl.cl_queue_properties;
import org.jocl.CL;
import static org.jocl.CL.clReleaseKernel;
import static org.jocl.CL.clReleaseProgram;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenCLContext {

    protected Logger logger = LoggerFactory.getLogger(this.getClass());
    public static final int GEN_PUBLIC_KEYS_MODE = 0;
    public static final int GEN_ADDRESSES_MODE = 1;
    public static final int GEN_SHA256_MODE = 2;
    public static final int GEN_RIPEMD160_MODE = 3;
    public static final int GEN_BYTEWISE_RIPEMD160_MODE = 4;
    public static final int GEN_BYTEWISE_2ND_SHA256_MODE = 5;
    public static final int GEN_BYTEWISE_3RD_SHA256_MODE = 6;
    public static final int GEN_BYTEWISE_ADDRESS_MODE = 7;
    private int[] errorCode = new int[1];

    public String[] getOpenCLPrograms() throws IOException {
        List<String> resourceNamesContent = getResourceNamesContent(getResourceNames());
        List<String> resourceNamesContentWithReplacements = new ArrayList<>();
        for (String content : resourceNamesContent) {
            String contentWithReplacements = content;
            contentWithReplacements = contentWithReplacements.replaceAll("#include.*", "");
            contentWithReplacements = contentWithReplacements.replaceAll("GLOBAL_AS const secp256k1_t \\*tmps", "const secp256k1_t \\*tmps");
            resourceNamesContentWithReplacements.add(contentWithReplacements);
        }
        String[] openClPrograms = resourceNamesContentWithReplacements.toArray(new String[0]);
        return openClPrograms;
    }

    private List<String> getResourceNames() {
        List<String> resourceNames = new ArrayList<>();
        resourceNames.add("inc_defines.h");
        resourceNames.add("copyfromhashcat/inc_vendor.h");
        resourceNames.add("copyfromhashcat/inc_types.h");
        resourceNames.add("copyfromhashcat/inc_platform.h");
        resourceNames.add("copyfromhashcat/inc_platform.cl");
        resourceNames.add("copyfromhashcat/inc_common.h");
        resourceNames.add("copyfromhashcat/inc_common.cl");

        resourceNames.add("copyfromhashcat/inc_ecc_secp256k1.h");
        resourceNames.add("copyfromhashcat/inc_ecc_secp256k1.cl");
        resourceNames.add("copyfromhashcat/inc_hash_sha256.h");
        resourceNames.add("copyfromhashcat/inc_hash_sha256.cl");
        resourceNames.add("copyfromhashcat/inc_hash_ripemd160.h");
        resourceNames.add("copyfromhashcat/inc_hash_ripemd160.cl");
        resourceNames.add("generator_utilities.cl");
        resourceNames.add("inc_ecc_secp256k1custom.cl");
        resourceNames.add("generate_btc_address.cl");
        return resourceNames;
    }

    private final static String PBK_NONCHUNK_KERNEL_NAME = "generateKeysKernel_grid";
    private final static String PBK_CHUNK_KERNEL_NAME = "generateKeyChunkKernel_grid";
    private static final String ADR_CHUNK_KERNEL_NAME = ""; // TODO define kernel name
    private static final String ADR_NONCHUNK_KERNEL_NAME = ""; // TODO define kernel name
    private final static String SHA256_CHUNK_KERNEL_NAME = "generateSha256ChunkKernel_grid";
    private final static String SHA256_NONCHUNK_KERNEL_NAME = "generateSha256Kernel_grid";
    private final static String RIPEMD160_CHUNK_KERNEL_NAME = "generateRipemd160ChunkKernel_grid";
    private final static String RIPEMD160_NONCHUNK_KERNEL_NAME = "generateRipemd160Kernel_grid";
    private final static String BYTEWISE_RIPEMD160_NONCHUNK_KERNEL = "generate_until_ripemd160";
    private final static String BYTEWISE_RIPEMD160_CHUNK_KERNEL = "generate_chunk_until_ripemd160";
    private final static String BYTEWISE_2ND_SHA256_CHUNK_KERNEL = "generate_chunk_until_second_sha256";
    private final static String BYTEWISE_2ND_SHA256_NONCHUNK_KERNEL = "generate_until_second_sha256";
    private final static String BYTEWISE_3RD_SHA256_CHUNK_KERNEL = "generate_chunk_until_third_sha256";
    private final static String BYTEWISE_3RD_SHA256_NONCHUNK_KERNEL = "generate_until_third_sha256";
    private final static String BYTEWISE_ADDRESS_CHUNK_KERNEL = "generate_chunk_until_address";

    private final static boolean EXCEPTIONS_ENABLED = true;
    
    private final CProducerOpenCL producerOpenCL;

    private cl_context_properties contextProperties;
    private cl_device_id device;
    private cl_context context;
    private cl_command_queue commandQueue;
    private cl_program program;
    private cl_kernel kernel;
    private OpenClTask openClTask;
    
    public OpenCLContext(CProducerOpenCL producerOpenCL) {
        this.producerOpenCL = producerOpenCL;
    }
    
    /**
     * Sets all properties and parameters to finally create the OpenCL kernel.
     *
     * @throws IOException When an error occurs while reading a resource.
     */
    public void init() throws IOException {
        
        // #################### general ####################
        
        // Enable exceptions and subsequently omit error checks in this sample
        CL.setExceptionsEnabled(EXCEPTIONS_ENABLED);
        
        // Obtain the number of platforms
        int numPlatformsArray[] = new int[1];
        clGetPlatformIDs(0, null, numPlatformsArray);
        int numPlatforms = numPlatformsArray[0];
        
        // Obtain a platform ID
        cl_platform_id platforms[] = new cl_platform_id[numPlatforms];
        clGetPlatformIDs(platforms.length, platforms, null);
        cl_platform_id platform = platforms[producerOpenCL.platformIndex];
        
        // Initialize the context properties
        contextProperties = new cl_context_properties();
        contextProperties.addProperty(CL_CONTEXT_PLATFORM, platform);
        
        // Obtain the number of devices for the platform
        int numDevicesArray[] = new int[1];
        clGetDeviceIDs(platform, producerOpenCL.deviceType, 0, null, numDevicesArray);
        int numDevices = numDevicesArray[0];
        
        // Obtain a device ID 
        cl_device_id devices[] = new cl_device_id[numDevices];
        clGetDeviceIDs(platform, producerOpenCL.deviceType, numDevices, devices, null);
        device = devices[producerOpenCL.deviceIndex];
        cl_device_id[] cl_device_ids = new cl_device_id[]{device};
        
        // Create a context for the selected device
        context = clCreateContext(contextProperties, 1, cl_device_ids, null, null, null);
        
        // Create a command-queue for the selected device
        cl_queue_properties properties = new cl_queue_properties();
        commandQueue = clCreateCommandQueueWithProperties(context, device, properties, null);
        
        // #################### kernel specifix ####################
        
        String[] openCLPrograms = getOpenCLPrograms();
        // Create the program from the source code
        program = clCreateProgramWithSource(context, openCLPrograms.length, openCLPrograms, null, null);

        // Build the program
        clBuildProgram(program, 0, null, null, null, null);
        
        // Create the kernel
        setKernel();

        openClTask = new OpenClTask(context, producerOpenCL);
    }

    private void setKernel() {
        if (producerOpenCL.kernelMode == GEN_PUBLIC_KEYS_MODE) {
            setPublicKeyGeneratorKernel();
        } else if (producerOpenCL.kernelMode == GEN_ADDRESSES_MODE) {
            setAddressGeneratorKernel();
        } else if (producerOpenCL.kernelMode == GEN_SHA256_MODE) {
            setSha256Kernel();
        } else if (producerOpenCL.kernelMode == GEN_RIPEMD160_MODE) {
            setRipemd150Kernel();
        } else if (producerOpenCL.kernelMode == GEN_BYTEWISE_RIPEMD160_MODE) {
            setBytewiseRipemd160Kernel();
        } else if (producerOpenCL.kernelMode == GEN_BYTEWISE_2ND_SHA256_MODE) {
            setBytewiseSecondSha256Kernel();
        } else if (producerOpenCL.kernelMode == GEN_BYTEWISE_3RD_SHA256_MODE) {
            setBytewiseThirdSha256Kernel();
        } else if (producerOpenCL.kernelMode == GEN_BYTEWISE_ADDRESS_MODE) {
            setBytewiseAddressKernel();
        } else {
            // TODO Implement else-case
        }
    }

    private void setPublicKeyGeneratorKernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, PBK_CHUNK_KERNEL_NAME, errorCode);
        } else {
            kernel = clCreateKernel(program, PBK_NONCHUNK_KERNEL_NAME, errorCode);
        }
    }

    private void setAddressGeneratorKernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, ADR_CHUNK_KERNEL_NAME, errorCode);
        } else {
            kernel = clCreateKernel(program, ADR_NONCHUNK_KERNEL_NAME, errorCode);
        }
    }

    private void setSha256Kernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, SHA256_CHUNK_KERNEL_NAME, errorCode);
        } else {
            kernel = clCreateKernel(program, SHA256_NONCHUNK_KERNEL_NAME, errorCode);
        }
    }

    private void setRipemd150Kernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, RIPEMD160_CHUNK_KERNEL_NAME, errorCode);
        } else {
            kernel = clCreateKernel(program, RIPEMD160_NONCHUNK_KERNEL_NAME, errorCode);
        }
    }

    private void setBytewiseRipemd160Kernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, BYTEWISE_RIPEMD160_CHUNK_KERNEL, errorCode);
        } else {
            kernel = clCreateKernel(program, BYTEWISE_RIPEMD160_NONCHUNK_KERNEL, errorCode);
        }
    }

    private void setBytewiseSecondSha256Kernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, BYTEWISE_2ND_SHA256_CHUNK_KERNEL, errorCode);
        } else {
            kernel = clCreateKernel(program, BYTEWISE_2ND_SHA256_NONCHUNK_KERNEL, errorCode);
        }
    }

    private void setBytewiseThirdSha256Kernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, BYTEWISE_3RD_SHA256_CHUNK_KERNEL, errorCode);
        } else {
            kernel = clCreateKernel(program, BYTEWISE_3RD_SHA256_NONCHUNK_KERNEL, errorCode);
        }
    }

    private void setBytewiseAddressKernel() {
        if (producerOpenCL.chunkMode) {
            kernel = clCreateKernel(program, BYTEWISE_ADDRESS_CHUNK_KERNEL, errorCode);
        } else {
            // TODO impl method
        }
    }

    public int getErrorCode() {
        return errorCode[0];
    }

    public String getErrorCodeString() {
        return CL.stringFor_errorCode(getErrorCode());
    }

    protected OpenClTask getOpenClTask() {
        return openClTask;
    }

    public void release() {
        openClTask.releaseCl();
        clReleaseKernel(kernel);
        clReleaseProgram(program);
        clReleaseCommandQueue(commandQueue);
        clReleaseContext(context);
    }

    /**
     * This method executes the OpenCL kernel to generate publicKeys or addresses, depending on the parameter
     * {@link CProducerOpenCL#kernelMode}.
     * <br><br>
     * The parameter {@link CProducerOpenCL#chunkMode} will determine if the given array has to be fully filled
     * with privateKeys or will only need a single one a the first element in the array.
     *
     * @param privateKeys In case of <strong>chunkMode = true</strong> this method only needs
     *                    one privateKey, but in case of <strong>chunkMode = false</strong>
     *                    it needs exactly as many private keys as the work size.
     * @return publicKeys or addresses as {@link OpenCLGridResult}
     */
    public OpenCLGridResult createResult(BigInteger[] privateKeys) {
        openClTask.setSrcPrivateKeys(privateKeys);
        ByteBuffer dstByteBuffer = openClTask.executeKernel(kernel, commandQueue);

        OpenCLGridResult openCLGridResult = null;
        try {
            openCLGridResult = new OpenCLGridResult(privateKeys, producerOpenCL.getWorkSize(), dstByteBuffer,
                    producerOpenCL.chunkMode, producerOpenCL.kernelMode);
        } catch (InvalidWorkSizeException e) {
            // TODO Handle a thrown InvalidWorkSizeException
            e.printStackTrace();
        }
        return openCLGridResult;
    }

    private static List<String> getResourceNamesContent(List<String> resourceNames) throws IOException {
        List<String> contents = new ArrayList<>();
        for (String resourceName : resourceNames) {
            URL url = Resources.getResource(resourceName);
            String content = Resources.toString(url, StandardCharsets.UTF_8);
            contents.add(content);
        }
        return contents;
    }
}