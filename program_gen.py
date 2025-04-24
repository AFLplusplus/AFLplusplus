'''
    The code organization work will be completed in the future. 
    Currently, it is still a bit messy, and there are many useless test codes.
'''

'''
    - Inputs:
        - `--output`: The path of the fuzzing output floder
    - Outputs
        - `./output/gen_seeds`: The generated seeds 
        - `./output/generators`: The generators extracted via LLM
    - Usage: 
        - python program_gen.py --output ./output --file_format tiff --mode init
        - python program_gen.py --output ./output --file_format tiff --mode incre
'''

# OpenAI Key
data = {
  "api_keys": [
    "<yourkey>"
  ],
  "api_base": "https://api.openai.com/v1"
}

# For each item: (Program name, [ALL FORMATS])
program_to_format = {
    "exiv2": ["jpg"],
    "gdk-pixbuf-pixdata":["gif", "bmp", "png", "pnm", "ico", "xmp", "ani", "pixdata", "tga"],
    "imginfo":["jpg", "pnm", "png", "mif", "bmp", "ras", "pgx", "ras"],
    "jhead":["jpg", "xmp"],
    "tiffsplit":["tiff"],
    "mp3gain":["mp3"],
    "wav2swf":["wav"],
    "ffmpeg":["mp4"],
    "flvmeta":["flv"],
    "mp42aac":["mp4"],
    "pdftotext":["pdf"],

    "libpng_read_fuzzer":["png"],
    "sndfile_fuzzer":["raw", "wav", "au", "aiff", "aifc", "mp3", "caf"],
    "tiff_read_rgba_fuzzer":["tiff"],
    "tiffcp":["tiff"],
    "pdf_fuzzer":["pdf"],
    "pdfimages":["pdf"],
    "pdftoppm":["pdf"],
    "asn1":["binary_large_object_BLOB"],
    "asn1parse":["binary_large_object_BLOB"],
    "bignum":["binary_large_object_BLOB"],
    "bndiv":["binary_large_object_BLOB"],
    "client":["binary_large_object_BLOB"],
    "cms":["binary_large_object_BLOB"],
    "conf":["binary_large_object_BLOB"],
    "crl":["binary_large_object_BLOB"],
    "ct":["binary_large_object_BLOB"],
    "server":["binary_large_object_BLOB"],
    "x509":["binary_large_object_BLOB"]
}



import argparse
import openai
import copy
import re
from openai_parallel_toolkit.api.keys import KeyManager
import logging
from openai_parallel_toolkit.utils.logger import LOG_LABEL
import os
import shutil
import time
import subprocess

# reference: https://github.com/ise-uiuc/TitanFuzz/blob/main/validate.py

import subprocess
import time
from enum import IntEnum, auto

CURRENT_TIME = time.time()

class ExecutionStatus(IntEnum):
    SUCCESS = auto()
    EXCEPTION = auto()
    CRASH = auto()
    NOTCALL = auto()
    TIMEOUT = auto()

def run_cmd(
    cmd_args,
    timeout=10,
    verbose=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    shell=False,
) -> (ExecutionStatus, str):
    try:
        output = subprocess.run(
            cmd_args, stdout=stdout, stderr=stderr, timeout=timeout, shell=shell
        )

    except subprocess.TimeoutExpired as te:
        if verbose:
            print("Timed out")
        return ExecutionStatus.TIMEOUT, ""
    else:
        if verbose:
            print("output.returncode: ", output.returncode)
        if output.returncode != 0:
            # 134 = Crash
            # 1 = exception
            error_msg = ""
            if output.stdout is not None:
                stdout_msg = output.stdout.decode("utf-8")
                stderr_msg = output.stderr.decode("utf-8")
                if verbose:
                    print("stdout> ", stdout_msg)
                if verbose:
                    print("stderr> ", stderr_msg)
                stdout_msg = stdout_msg[:30]
                error_msg = "---- returncode={} ----\nstdout> {}\nstderr> {}\n".format(
                    output.returncode, stdout_msg, stderr_msg
                )

            if output.returncode == 134:  # Failed assertion
                return ExecutionStatus.CRASH, "SIGABRT Triggered\n" + error_msg
            elif output.returncode == 132:
                return ExecutionStatus.CRASH, "SIGILL\n" + error_msg
            elif output.returncode == 133:
                return ExecutionStatus.CRASH, "SIGTRAP\n" + error_msg
            elif output.returncode == 136:
                return ExecutionStatus.CRASH, "SIGFPE\n" + error_msg
            elif output.returncode == 137:
                return ExecutionStatus.CRASH, "OOM\n" + error_msg
            elif output.returncode == 138:
                return ExecutionStatus.CRASH, "SIGBUS Triggered\n" + error_msg
            elif output.returncode == 139:
                return (
                    ExecutionStatus.CRASH,
                    "Segmentation Fault Triggered\n" + error_msg,
                )
            else:
                if output.returncode != 1:
                    # Check Failed: -6
                    print("output.returncode: ", output.returncode)
                    print(cmd_args)
                    print("stdout> ", stdout_msg)
                    print("stderr> ", stderr_msg)
                    return ExecutionStatus.CRASH, error_msg
                else:
                    return ExecutionStatus.EXCEPTION, error_msg
        else:
            if verbose:
                stdout_msg = output.stdout.decode("utf-8")
                print("stdout> ", stdout_msg)
            return ExecutionStatus.SUCCESS, ""

def validate_status_process(
    g_code, python="python", device="cpu", verbose=False
) -> (ExecutionStatus, str):
    with open("/tmp/tmp{}.py".format(CURRENT_TIME), "w") as f:
        f.write(g_code)
    # print("/tmp/tmp{}.py".format(CURRENT_TIME))
    run_args = [python, "/tmp/tmp{}.py".format(CURRENT_TIME)]
    status, msg = run_cmd(run_args, verbose=verbose)
    return status, msg

messages_analyze_structure = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple sections."},
    {"role": "user", "content": "Give the main components of a TIFF file"},
    {"role": "assistant", "content": "The main components of a TIFF (Tagged Image File Format) file include:\n1.Header: The header contains essential information about the TIFF file, such as its byte order (either little-endian or big-endian), the version of the TIFF format being used, and the offset to the first Image File Directory (IFD). The header is usually 8 bytes in size.\n2.Image File Directory (IFD): The IFD is a critical part of a TIFF file, acting as a directory that points to various metadata tags describing the image. These tags include information such as image dimensions, color depth, compression method, and more. Each entry in the IFD consists of a tag number, a data type, and a data field. The IFD also includes an offset pointing to the next IFD if multiple images are stored in the file.\n3.Image Data: This section contains the actual pixel data that makes up the image. The format of the image data depends on factors such as color space and compression method. Common color spaces include RGB and CMYK, while common compression methods include LZW, ZIP, JPEG, and PackBits.\nThese components collectively define the structure of a TIFF file.\n"},
    {"role": "user", "content": "Give the main components of a JPEG file"},
    {"role": "assistant", "content": "The main components of a JPEG (Joint Photographic Experts Group) file include:\n1.SOI Marker (Start of Image): A 2-byte marker denoting the beginning of the JPEG file. \n2.APP Markers (Application Segment Markers): These are markers used for application-specific metadata. For example, the APP0 marker (JFIF marker) contains information about the file format. \n3.DQT Marker (Define Quantization Table): Specifies the quantization tables used for compressing the image. \n4.SOF Marker (Start of Frame): Marks the beginning of the frame and contains information about the image dimensions, color components, and sampling factors. \n5.DHT Marker (Define Huffman Table): Specifies the Huffman tables used for entropy coding. \n6.SOS Marker (Start of Scan): Marks the beginning of the scan data and includes information about the color components and the Huffman coding tables used. \n7.Image Data (Scan Data): Contains the compressed image data. \n8.EOI Marker (End of Image): A 2-byte marker denoting the end of the JPEG file.\nThese components collectively define the structure of a JPEG file.\n"},
    {"role": "user", "content": ""}
]
messages_analyze_structure_prompt = "# Based on the above thought process and format, answer the question.\nGive the main components of a <TARGET> file"

messages_analyze_structure_2 = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple sections."},
    {"role": "user", "content": "Give all necessary and optional sections of a TIFF file"},
    {"role": "assistant", "content": "A TIFF (Tagged Image File Format) file is a flexible and extensible format commonly used for storing raster graphics images. It supports various compression schemes and color spaces. Here are the main sections found in a TIFF file:\n\n1. Header (Necessary):\n   - Byte Order: A 2-byte identifier indicating the byte order of the file (either \"II\" for little-endian or \"MM\" for big-endian).\n   - 42 (0x2A): A 2-byte identifier (42 in decimal) indicating the TIFF file format.\n   - Offset to First IFD: A 4-byte offset specifying the location of the first Image File Directory (IFD).\n\n2. Image File Directory (IFD) (Necessary):\n   - Tag Entries: A series of tag entries, each containing information about the image data, such as width, height, compression, and color space.\n   - Next IFD Offset: A 4-byte offset pointing to the next IFD. If this field is 0, there are no additional IFDs.\n\n3. Image Data (Necessary):\n   - The actual pixel data of the image.\n\n4. IFD Entries (Necessary):\n   - Each IFD entry includes a tag, a field type, a field count, and a field value. Common IFD tags include:\n     - Image Width (Tag 256)\n     - Image Height (Tag 257)\n     - Bits Per Sample (Tag 258)\n     - Compression (Tag 259)\n     - Photometric Interpretation (Tag 262)\n     - Strip Offsets (Tag 273)\n     - Samples Per Pixel (Tag 277)\n     - Rows Per Strip (Tag 278)\n     - Strip Byte Counts (Tag 279)\n     - X Resolution (Tag 282)\n     - Y Resolution (Tag 283)\n     - Planar Configuration (Tag 284)\n     - Resolution Unit (Tag 296)\n     - Color Map (Tag 320)\n     - Compression Scheme-specific Tags (various)\n\n5. Strip or Tile Data (Necessary):\n   - Depending on the configuration, image data may be organized into strips or tiles.\n\n6. Additional IFDs (Optional):\n   - TIFF files may include multiple IFDs, each pointing to different image data. This is useful for multi-page documents or images with multiple layers.\n\n7. XMP Metadata (Optional):\n   - Some TIFF files may include Extensible Metadata Platform (XMP) data for additional metadata.\n\n8. ICC Profile (Optional):\n   - An ICC color profile can be embedded for accurate color representation.\n\n9. Private or Vendor-Specific Tags (Optional):\n   - TIFF allows for the inclusion of private or vendor-specific tags to accommodate additional information.\n\nIt\'s important to note that TIFF is a flexible format, and the specific tags and sections present in a file depend on the features used and the requirements of the application that generated the TIFF file.\n"},
    {"role": "user", "content": "Give all necessary and optional sections of a JPEG file"},
    {"role": "assistant", "content": "A JPEG (Joint Photographic Experts Group) file is a common format for compressing and storing digital images. It uses lossy compression to reduce file size while retaining a reasonable level of image quality. Here are the main sections found in a JPEG file:\n\n1. SOI Marker (Necessary):\n   - Start of Image marker (0xFFD8) indicating the beginning of the JPEG file.\n\n2. APP Markers (Optional):\n   - APP markers are application-specific markers that can store additional metadata. Common APP markers include:\n      - APP0 (0xFFE0): JFIF (JPEG File Interchange Format) marker, containing information like pixel aspect ratio and thumbnail data.\n      - APP1 (0xFFE1): Exif (Exchangeable image file format) marker, storing metadata such as camera settings and location information.\n      - APP2 (0xFFE2): ICC profile marker, for embedding color profiles.\n\n3. DQT Marker (Necessary):\n   - Define Quantization Table marker (0xFFDB) specifying the quantization tables used for compressing image data.\n\n4. SOF Marker (Necessary):\n   - Start of Frame marker (0xFFC0 or 0xFFC2) indicating the beginning of the frame header.\n   - Specifies parameters like image dimensions, color components, and sampling factors.\n\n5. DHT Marker (Necessary):\n   - Define Huffman Table marker (0xFFC4) specifying the Huffman coding tables used for entropy encoding.\n\n6. SOS Marker (Necessary):\n   - Start of Scan marker (0xFFDA) indicating the beginning of the scan header.\n   - Contains information about the components in the scan, along with references to the Huffman tables.\n\n7. Image Data (Necessary):\n   - The compressed image data using Huffman coding and quantization tables.\n\n8. EOI Marker (Necessary):\n   - End of Image marker (0xFFD9) indicating the end of the JPEG file.\n\nOptional sections, such as APP markers, allow for the inclusion of additional information and metadata in the JPEG file. The actual content of the image is represented by the SOF marker, DQT marker, DHT marker, SOS marker, and the compressed image data.\n\nIt's important to note that the presence of specific markers and their order can vary in JPEG files. The JPEG standard is flexible, allowing for different configurations and optional markers to support various applications and metadata needs.\n"},
    {"role": "user", "content": "Give all necessary and optional sections of a flv file"},
    {"role": "assistant", "content": "FLV (Flash Video) files have a structure that includes both necessary and optional sections. FLV is a multimedia container format used for streaming video and audio content over the internet. Here are the main sections found in an FLV file:\n\n1. FLV Header (Necessary):\n   - Signature: A 3-byte sequence that identifies the file as an FLV (usually \"FLV\").\n   - Version: A byte indicating the version of the FLV format.\n   - Flags: A byte containing various flags, including the presence of audio and video tags.\n\n2. PreviousTagSize0 (Necessary):\n   - A 4-byte field indicating the size of the previous FLV tag. This value is set to 0 for the first tag.\n\n3. FLV Tags (Necessary):\n   - FLV files consist of a series of tags, each representing a unit of audio, video, or metadata.\n   - Tag Type: A byte indicating the type of the tag (audio, video, script).\n   - Data Size: A 3-byte field indicating the size of the tag data.\n   - Timestamp: A 4-byte field indicating the timestamp of the tag in milliseconds.\n   - StreamID: A 3-byte field reserved for multiplexing several streams into a single file.\n   - Tag Data: Contains the actual audio, video, or metadata payload.\n\n4. MetaTag (Optional):\n   - A special type of tag used for metadata. It contains information about the video, audio, and other properties.\n   - Tag Type: 0x12 (18 in decimal) indicating a metadata tag.\n   - Data Size: The size of the metadata tag data.\n   - Tag Data: Contains information about the video and audio properties.\n\n5. Video and Audio Tags (Necessary):\n   - Tags of type 0x08 (audio) and 0x09 (video) contain the actual audio and video data.\n   - The structure of these tags includes codec information, frame data, and timestamps.\n\n6. ScriptTag (Optional):\n   - A special type of tag used for ActionScript, the scripting language used in Flash.\n   - Tag Type: 0x12 (18 in decimal) indicating a script tag.\n   - Data Size: The size of the script tag data.\n   - Tag Data: Contains ActionScript instructions.\n\n7. PreviousTagSize (Necessary):\n   - A 4-byte field indicating the size of the previous FLV tag. This value allows the parser to locate the next tag in the file.\n\nIt\'s important to note that while the FLV header, PreviousTagSize0, and the basic structure of FLV tags are necessary for a valid FLV file, the presence of certain tags (such as meta tags and script tags) depends on the content and the way the FLV file is structured. FLV files are commonly used for streaming video, and the structure allows for the interleaving of audio and video data.\n"},
    {"role": "user", "content": ""}
]
messages_analyze_structure_prompt_2 = "# Based on the above thought process and format, answer the question.\nGive all necessary and optional sections of a <TARGET> file"

messages_analyze_structure_3 = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple sections."},
    {"role": "user", "content": "Give all necessary and optional sections of a TIFF file"},
    {"role": "assistant", "content": "In a TIFF (Tagged Image File Format) file, there are necessary sections that are fundamental to the file structure, as well as optional sections that may be included for specific purposes or features. Here are the necessary and common optional sections:\n\nNecessary Sections:\n\n1. Header (Necessary):\n   - Byte Order: Indicates the byte order of the file (little-endian or big-endian).\n   - TIFF Identifier: A 2-byte identifier (42 for big-endian, 18761 for little-endian) that marks the file as a TIFF file.\n\n2. IFD (Image File Directory) (Necessary):\n   - Offset to the IFD, which is a table containing entries describing the image properties.\n   - Each entry includes a tag, field type, and field value.\n\n3. Image Data (Necessary):\n   - Contains the actual pixel data of the image.\n\nOptional Sections:\n\n1. IFD (Image File Directory) (Optional):\n   - Additional IFDs may be present, allowing for multiple images within a single TIFF file.\n\n2. ICC Profile (Optional):\n   - International Color Consortium profile data, providing color information for accurate color reproduction.\n\n3. Image Description (Optional):\n   - A human-readable description of the image.\n\n4. Thumbnail (Optional):\n   - A smaller version of the image for preview purposes.\n\n5. GPS Info (Optional):\n   - Geographic information, such as latitude, longitude, and altitude, if applicable.\n\n6. Exif Data (Optional):\n   - Additional metadata related to the camera settings and conditions when the image was captured.\n\n7. Software (Optional):\n   - Information about the software used to create or modify the image.\n\n8. Copyright (Optional):\n   - Copyright information related to the image.\n\n9. Alpha Channel (Optional):\n   - Additional channel(s) for storing transparency information.\n\n10. Private or Custom Tags (Optional):\n    - TIFF is extensible, allowing for the inclusion of custom tags and data specific to certain applications or requirements.\n\nThese sections provide a basic overview, and the actual structure may vary depending on the TIFF version and extensions used. The TIFF format is flexible and extensible, allowing for customization to meet specific needs."},
    # {"role": "user", "content": "Give all necessary and optional sections of a JPEG file"},
    # {"role": "assistant", "content": "JPEG (Joint Photographic Experts Group) is a widely used image compression format, and it doesn't have distinct sections like some other file formats such as GIF or TIFF. However, a JPEG file typically consists of the following components:\n\nNecessary Components:\n\n1. SOI (Start of Image Marker):\n   - Marks the beginning of the JPEG image data.\n\n2. APPn (Application Markers):\n   - Contains application-specific information. For example, `APP0` may contain JFIF (JPEG File Interchange Format) information.\n\n3. DQT (Quantization Table):\n   - Specifies the quantization tables used in the image compression.\n\n4. SOF0 (Start of Frame Marker):\n   - Provides information about the image such as dimensions and color space.\n\n5. DHT (Huffman Table):\n   - Defines the Huffman tables used for entropy encoding.\n\n6. SOS (Start of Scan Marker):\n   - Indicates the start of the actual image data.\n\n7. Image Data (Entropy-encoded):\n   - The compressed image data itself.\n\n8. EOI (End of Image Marker):\n   - Marks the end of the JPEG image data.\n\nOptional Components:\n\n1. COM (Comment Marker):\n   - Allows for comments or additional information to be stored in the file.\n\n2. DRI (Define Restart Interval Marker):\n   - Specifies the interval between restart markers.\n\n3. DNL (Define Number of Lines Marker):\n   - Specifies the number of lines in the restart interval.\n\n4. DHP (Define Hierarchical Progression Marker):\n   - Used in progressive JPEGs to define a hierarchical progression.\n\n5. DAC (Define Arithmetic Coding Conditioning Marker):\n   - Used to define arithmetic coding conditioning.\n\n6. Markers for Application-specific Data:\n   - For example, Adobe APP14 marker may contain information related to Adobe applications.\n\nJPEG is a lossy compression format, and the actual image data is typically the largest and most critical part of the file. The optional markers are used for specific purposes and are not always present in every JPEG file. The overall structure and content of JPEG files may vary based on factors such as color space, subsampling, and whether the image is baseline or progressive."},
    {"role": "user", "content": "Give all necessary and optional sections of a FLV file"},
    {"role": "assistant", "content": "A FLV (Flash Video) file is a container format used to deliver video content over the internet. It typically contains video and audio streams and can also include metadata. Here are the necessary and optional sections commonly found in a FLV file:\n\nNecessary Sections:\n\n1. FLV Header (Necessary):\n   - Signature: A 3-byte signature ('FLV') that identifies the file as a FLV file.\n   - Version: A 1-byte version number.\n   - Flags: A 5-byte field containing various flags.\n\n2. PreviousTagSize0 (Necessary):\n   - A 4-byte field representing the size of the previous tag in the FLV file. This field helps in locating the start of the next tag.\n\n3. Tag (Necessary):\n   - Tags contain audio, video, or metadata. Each tag has a header followed by data.\n   - Tag Header: Contains information about the tag, such as tag type, data size, timestamp, and stream ID.\n   - Tag Data: Actual audio, video, or metadata payload.\n\nOptional Sections:\n\n1. Script Data (Optional):\n   - Script data tag can be used to embed metadata, cue points, and other information. It is often used for ActionScript communication with Flash Player.\n\n2. Cue Points (Optional):\n   - Provides information about cue points in the video, allowing for navigation to specific points in the content.\n\n3. Keyframes (Optional):\n   - Index of keyframes in the video, allowing for efficient seeking and playback.\n\n4. Sound (Optional):\n   - Contains audio data, including codec information, sample rate, and channel count.\n\n5. Video (Optional):\n   - Contains video data, including codec information, frame rate, and dimensions.\n\n6. Metadata (Optional):\n   - Additional metadata associated with the video content.\n\n7. User Data (Optional):\n   - User-specific data or custom extensions.\n\n8. AMF Data (Optional):\n   - AMF (Action Message Format) data used for communication between Flash Player and server-side applications.\n\n9. Encryption (Optional):\n   - FLV files may be encrypted for security purposes.\n\nIt's important to note that the specific structure and content of FLV files may vary based on the codecs used for audio and video, the presence of metadata, and any custom extensions employed. The FLV format is flexible, allowing for various configurations to meet specific requirements."},
    {"role": "user", "content": ""}
]
messages_analyze_structure_prompt_3 = "# Based on the above thought process and format, answer the question.\nGive all necessary and optional sections of a <TARGET> file"

messages_analyze_structure_necessary = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple components."},
    {"role": "user", "content": "Give all necessary components of a TIFF file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."},
    {"role": "assistant", "content": "A TIFF (Tagged Image File Format) file consists of several necessary components. TIFF is a flexible format that supports various compression schemes, color spaces, and metadata. Here are the main necessary components commonly found in a TIFF file:\n\n1. Header:\n   - Byte Order: Indicates the byte order of the file (little-endian or big-endian).\n   - TIFF Identifier: A 2-byte identifier (42 for big-endian, 18761 for little-endian) that marks the file as a TIFF file.\n\n2. IFD (Image File Directory):\n   - Offset to the IFD, which is a table containing entries describing the image properties.\n   - Each entry includes a tag, field type, and field value.\n\n3. Image Data:\n   - Contains the actual pixel data of the image."},
    {"role": "user", "content": "Give all necessary components of a JPEG file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."},
    {"role": "assistant", "content": "JPEG (Joint Photographic Experts Group) files primarily consist of image data and do not have distinct components in the way that some other file formats do. The structure of a JPEG file revolves around markers and segments. Here are the necessary components commonly found in a JPEG file:\n\n1. SOI (Start of Image Marker):\n   - Marks the beginning of the JPEG image data.\n\n2. APPn (Application Markers):\n   - Contains application-specific information. For example, `APP0` may contain JFIF (JPEG File Interchange Format) information.\n\n3. DQT (Quantization Table):\n   - Specifies the quantization tables used in the image compression.\n\n4. SOFn (Start of Frame Marker):\n   - Provides information about the image, such as dimensions, color space, and other parameters.\n\n5. DHT (Huffman Table):\n   - Defines the Huffman tables used for entropy encoding.\n\n6. SOS (Start of Scan Marker):\n   - Indicates the start of the actual image data.\n\n7. Image Data (Entropy-encoded):\n   - The compressed image data itself.\n\n8. EOI (End of Image Marker):\n   - Marks the end of the JPEG image data."},
    {"role": "user", "content": "Give all necessary components of a GIF file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."},
    {"role": "assistant", "content": "The necessary components of a GIF (Graphics Interchange Format) file include the following:\n\n1. Header:\n   - Signature: A 3-byte sequence (\"GIF\") that identifies the file as a GIF.\n   - Version: A 3-byte sequence indicating the GIF version (\"87a\" or \"89a\").\n\n2. Logical Screen Descriptor:\n   - Canvas Size: Width and height of the canvas in pixels.\n   - Global Color Table Flag: Indicates whether a global color table is present.\n   - Background Color Index: Index into the global color table for the background color.\n   - Pixel Aspect Ratio: Ratio of the width to the height of a pixel.\n\n3. Global Color Table:\n   - A color table containing up to 256 colors used for the entire image.\n\n4. Image Descriptor and Data:\n   - Image Descriptor: Contains image-specific information such as image position and size.\n   - Image Data: Raw pixel data encoded using LZW compression.\n\n5. Trailer:\n   - A single byte with the value 0x3B indicating the end of the GIF file."},
    {"role": "user", "content": ""}
]
messages_analyze_structure_necessary_prompt = "# Based on the above thought process and format, answer the question.\nGive all necessary components of a <TARGET> file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."

messages_analyze_structure_optional = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple components."},
    {"role": "user", "content": "Give all necessary components of a TIFF file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."},
    {"role": "assistant", "content": "The TIFF (Tagged Image File Format) is a flexible format that allows for various optional components and extensions, depending on the specific needs of the image data. Here are some of the optional components that may be found in a TIFF file:\n\n1. ICC Profile:\n   - International Color Consortium profile data, providing color information for accurate color reproduction.\n\n2. Exif Data:\n   - Exchangeable Image File Format data, containing metadata related to the camera settings and conditions when the image was captured.\n\n3. GPS Info:\n   - Geographic information, such as latitude, longitude, and altitude, if applicable.\n\n4. Thumbnail:\n   - A smaller version of the image for preview purposes.\n\n5. Subfile Type:\n   - Specifies the type of data stored in the TIFF file, indicating whether it is a full image, reduced-resolution image, or other types.\n\n6. Image Description:\n   - A human-readable description or title of the image.\n\n7. Software:\n   - Information about the software used to create or modify the image.\n\n8. Copyright:\n   - Copyright information related to the image.\n\n9. Alpha Channel:\n   - Additional channel(s) for storing transparency information.\n\n10. Private or Custom Tags:\n    - TIFF allows for the inclusion of private or custom tags, which can be used to store application-specific data."},
    {"role": "user", "content": "Give all necessary components of a JPEG file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."},
    {"role": "assistant", "content": "JPEG (Joint Photographic Experts Group) files can include optional markers and segments for various purposes. While JPEG itself doesn\'t have distinct \"components\" like some other file formats, it uses markers to delineate different parts of the file. Here are some optional markers and components that can be found in a JPEG file:\n\n1. COM (Comment Marker):\n   - Allows for comments or additional information to be stored in the file.\n\n2. DRI (Define Restart Interval Marker):\n   - Specifies the interval between restart markers.\n\n3. DNL (Define Number of Lines Marker):\n   - Specifies the number of lines in the restart interval.\n\n4. DHP (Define Hierarchical Progression Marker):\n   - Used in progressive JPEGs to define a hierarchical progression.\n\n5. DAC (Define Arithmetic Coding Conditioning Marker):\n   - Used to define arithmetic coding conditioning.\n\n6. APPn (Application Markers):\n   - Contains application-specific information. For example, `APP1` might contain Exif data.\n\n7. Quantization Table:\n   - Specifies custom quantization tables for image compression.\n\n8. Restart Markers:\n   - Used for error recovery. Specifies locations where the entropy decoding process should be restarted.\n\n9. Adobe APP14 Marker:\n   - Contains information specific to Adobe applications.\n\n10. XMP (Extensible Metadata Platform Marker):\n    - Stores metadata using the XMP standard."},
    {"role": "user", "content": "Give all necessary components of a GIF file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."},
    {"role": "assistant", "content": "GIF (Graphics Interchange Format) files may include various optional components to support additional features or extensions. Here are some of the optional components that can be found in a GIF file:\n\n1. Graphics Control Extension:\n   - Used to control aspects of display, including transparency, delay time, and disposal method for the current or subsequent frames.\n\n2. Comment Extension:\n   - Used to store textual comments for documentation or other purposes.\n\n3. Plain Text Extension:\n   - Allows for the inclusion of text strings in the GIF file in a plain text format.\n\n4. Application Extension:\n   - Used for application-specific extensions. For example, the Netscape extension is commonly used for looping animated GIFs.\n\n5. Image Descriptor and Data:\n   - While the Image Descriptor and Data are necessary for each frame, the use of multiple frames for animation is optional."},
    {"role": "user", "content": ""}
]
messages_analyze_structure_optional_prompt = "# Based on the above thought process and format, answer the question.\nGive all optional components of a <TARGET> file. Emphasize the names of each component using Markdown's ordered list syntax, i.e., '1.Component Name'."

messages_decompose = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple components."},
    {"role": "user", "content": "Can a Data Type in 'a Directory Entries (Tags) in an IFD in a TIFF file' be decomposed into smaller components? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Analysis: The Data Type is a fixed-size field that directly specifies the format of the associated data values, and it does not have internal subcomponents. \n2. Result: Therefore, the answer is **no**\n"},
    {"role": "user", "content": "Can an Entry Count in 'an IFD (Image File Directory) in a TIFF file' be decomposed into smaller components? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Analysis: The Entry Count is a single integral value that indicates the number of values or elements associated with a specific tag in the IFD. It is not further subdivided into smaller components; rather, it represents a simple integer value. \n2. Result: Therefore, the answer is **no**\n"},
    {"role": "user", "content": "Can an IFD (Image File Directory) in 'a TIFF file' be decomposed into smaller components? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Analysis: The IFD itself consists of multiple components, including the number of directory entries, directory entries (tags), and the next IFD offset. Each directory entry has components such as the tag ID, data type, data count, and data values.\n2. Result: Therefore, the answer is **yes**.\n"},
    {"role": "user", "content": "Can a Directory Entries (Tags) in 'an IFD (Image File Directory) in a TIFF file' be decomposed into smaller components? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Analysis: The IFD itself consists of multiple components, including the number of directory entries, directory entries (tags), and the next IFD offset. Each directory entry has components such as the tag ID, data type, data count, and data values.\n2. Result: Therefore, the answer is **yes**.\n"},
    {"role": "user", "content": ""}
]
messages_decompose_prompt = "Can a <TARGET> in '<POS>' be decomposed into smaller components? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"
messages_decompose_prompt_origin = "Can a <TARGET> be decomposed into smaller components? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"

messages_decompose_size = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple components."},
    {"role": "user", "content": "Does a tiff have a fixed size? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "The size of a TIFF file can vary depending on the content and the compression used. Therefore, the answer is **no**."},
    {"role": "user", "content": "Does a Tag Count in 'IFD in a tiff' have a fixed size? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "The Tag Count is a 16-bit unsigned integer field that specifies the number of entries (tags) in the IFD. Therefore, the answer is **yes**."},
    {"role": "user", "content": ""}
]
size_prompt = "Does a <TARGET> in '<POS>' have a fixed size? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"
size_prompt_origin = "Does a <TARGET> have a fixed size? Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"



# Definition of Specific data structure: A specific data structure is characterized by the ability to divide the bytes within an item into multiple segments with distinct meanings.
messages_decompose_specific = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple components."},
    {"role": "user", "content": "In 'a TIFF file', is 'Image Data' a specific data structure? Task1: Explain the reason. Task2: If yes, provide the structural definition. Task3: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Explain the reason: In a TIFF file, 'Image Data' is not a specific data structure; instead, it refers to the actual pixel values that constitute the image.  \n2. If yes, provide the structural definition: None. \n3. Emphasize the 'yes/no' result using Markdown's bold syntax: **No**."},
    {"role": "user", "content": "In 'a TIFF file', is 'Image File Directory (IFD)' a specific data structure? Task1: Explain the reason. Task2: If yes, provide the structural definition. Task3: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Explain the reason: 'Image File Directory (IFD)' is a specific data structure in a TIFF file. It serves as a directory that contains metadata about the image, including details such as image dimensions, color space, compression methods, and other attributes.\n2. If yes, provide the structural definition: The structural definition of the 'Image File Directory (IFD)' involves a set of entries, each representing a specific tag with its corresponding value. These entries contain essential metadata about the image, forming a hierarchical structure. The IFD can also reference other IFDs, allowing for the representation of more complex image arrangements.\n3. Emphasize the 'yes/no' result using Markdown's bold syntax: **Yes**"},
    {"role": "user", "content": "In 'Image Data in a TIFF file', is 'Metadata' a specific data structure? Task1: Explain the reason. Task2: If yes, provide the structural definition. Task3: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Explain the reason: 'Metadata' in the context of 'Image Data in a TIFF file' is not a specific data structure. Instead, it refers to information about the image, such as its characteristics, properties, and other descriptive details. Metadata in a TIFF file is typically stored in the Image File Directory (IFD) and is not a standalone structure.\n2. If yes, provide the structural definition: None\n3. Emphasize the 'yes/no' result using Markdown's bold syntax: **No**"},
    {"role": "user", "content": "In 'Image Data in a tiff', is 'Bit Depth' a specific data structure? Task1: Explain the reason. Task2: If yes, provide the structural definition. Task3: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Explain the reason: No, 'Bit Depth' is not a specific data structure; instead, it is a characteristic that describes the precision of pixel values in the image. Bit depth indicates the number of bits used to represent each pixel and influences the range of colors or shades of gray that can be represented.\n2. If yes, provide the structural definition: None\n3. Emphasize the 'yes/no' result using Markdown's bold syntax: **No**"},
    {"role": "user", "content": ""}
]
specific_prompt = "In '<POS>', is '<TARGET>' a specific data structure? Task1: Explain the reason. Task2: If yes, provide the structural definition. Task3: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"

messages_decompose_num = [
    {"role": "system", "content": "You are a parser that can parse any file into multiple components."},
    {"role": "user", "content": "In 'a IFD (Image File Directory) in a tiff', is 'Next IFD Offset' a numeric field? Task 1: Explain the reason. Task 2: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Explain the reason: Yes, 'Next IFD Offset' is a numeric field in the Image File Directory (IFD) of a TIFF (Tagged Image File Format). This field is used to indicate the offset (a numerical value representing the distance in bytes) from the beginning of the TIFF file to the location of the next IFD. It points to the start of the next IFD in the file structure.\n2. Emphasize the 'yes/no' result using Markdown's bold syntax: **Yes**"},
    {"role": "user", "content": "In 'a tiff', is 'IFD (Image File Directory)' a numeric field? Task 1: Explain the reason. Task 2: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"},
    {"role": "assistant", "content": "1. Explain the reason: No, 'IFD' (Image File Directory) itself is not a numeric field; rather, it is a structural element in the TIFF file format. The IFD contains various entries, each of which includes numeric fields such as tag, type, count, and offset.\n2. Emphasize the 'yes/no' result using Markdown's bold syntax: **No**"},
    {"role": "user", "content": ""}
]
num_prompt = "In '<POS>', is '<TARGET>' a numeric field? Task 1: Explain the reason. Task 2: Emphasize the 'yes/no' result using Markdown's bold syntax, i.e., **yes/no**"



messages_analyze_sub_structure = [
    {"role": "user", "content": "Give the main components of a IFD in a TIFF file. If IFD cannot be further decomposed into smaller components, return \"none\"."},
    {"role": "assistant", "content": "The main components of an Image File Directory (IFD) in a TIFF (Tagged Image File Format) file include:  \n1.Number of Directory Entries: A 2-byte field specifying the number of entries (tags) contained within the IFD. \n2.Directory Entries (Tags): Each tag consists of 12 bytes\n3.Next IFD Offset: A 4-byte field specifying the offset to the next IFD in the TIFF file. If this value is 0, it indicates the end of the IFD chain.\nThese components collectively define the structure of an IFD in a TIFF file, providing metadata about the image through various tags.\n"},
    {"role": "user", "content": "Give the main components of Directory Entries (Tags) in a IFD in a TIFF file. If Directory Entries (Tags) cannot be further decomposed into smaller components, return \"none\"."},
    {"role": "assistant", "content": "The main components of Directory Entries (Tags) in an Image File Directory (IFD) in a TIFF (Tagged Image File Format) file include:  \n1.Tag ID (Field Type): A 2-byte numerical identifier representing the type of information stored in the tag. It specifies the attribute or property of the image that the tag describes. \n2.Data Type: A 2-byte field specifying the data type of the values stored in the tag. Different data types define how the data field should be interpreted. Common data types include BYTE, ASCII, SHORT, LONG, RATIONAL, among others. \n3.Data Count: A 4-byte field indicating the number of values or data elements associated with the tag. It defines how many values are present in the data field. \n4.Data Offset or Value(s): Depending on the data type and data count, this field contains either the actual data values or an offset pointing to the location in the file where the data is stored. If the data fits within 4 bytes, it is stored directly in this field. Otherwise, the offset points to the location of the data elsewhere in the file. \nThese components together define the structure of each tag within the IFD.\n"},
    {"role": "user", "content": ""}
]
messages_analyze_sub_structure_prompt = "# Based on the above thought process and format, answer the question.\nGive the main components of <POS>. If <TARGET> cannot be further decomposed into smaller components, return \"none\"."

messages_check = [
    {"role": "user", "content": "In a tiff file, do IFD and TAG not contain each other?"},
    {"role": "assistant", "content": "1.Analyze each component: \n\ta)Image File Directory (IFD): The IFD is a data structure that contains entries (tags) storing metadata information about the image. Each entry points to specific details such as image dimensions, compression method, color information, etc. \n\tb)Tags (TAG): Tags are individual components within the IFD, representing specific attributes or parameters related to the image. \n2.Analyze their relationship: Tags are components within the IFD, forming a hierarchical structure where the IFD contains tags. Tags hold metadata information, and the IFD serves as a container or directory for these tags. \n3.Give the answer: Thus, the answer is 'no.'\n"},
    {"role": "user", "content": "In a tiff file, do IFD and Image Data not contain each other?"},
    {"role": "assistant", "content": "1.Analyze each component: \n\ta)Image File Directory (IFD): The IFD is a data structure that contains entries (tags) storing metadata information about the image. Each entry points to specific details such as image dimensions, compression method, color information, etc. \n\tb)Image Data: This section typically follows the IFD and contains the actual pixel data that makes up the image. \n2.Analyze their relationship: The IFD and Image Data sections do not directly contain each other. The IFD holds metadata information, while the Image Data section holds the pixel data, and they are separate components within the TIFF file structure.\n3.Give the answer: Thus, the answer is 'yes.' \n"},
    {"role": "user", "content": "In a jpeg file, do SOI, DQT, DHT, and SOF not contain each other?"},
    {"role": "assistant", "content": "1.Analyze each component: \na)Start of Image (SOI): SOI is a marker that indicates the beginning of a JPEG file. \nb)Quantization Table (DQT): DQT defines the quantization table used for compressing image data. \nc)Huffman Table (DHT): DHT defines the Huffman table used for entropy encoding. \nd)Start of Frame (SOF): SOF specifies the parameters of the image, such as its dimensions and color information. \n2.Analyze their relationship: SOI marks the start of the JPEG file. DQT and DHT provide tables used in the compression process. SOF defines the image parameters. In a JPEG file, these components (SOI, DQT, DHT, and SOF) are interrelated, as they collectively contribute to the structure and encoding of the JPEG image.\n3.Give the answer: Thus, the answer is 'no.'\n"},
    {"role": "user", "content": ""}
]
messages_check_prompt = "# Based on the above thought process and format, answer the question.\nIn <POS>, do <TARGET> not contain each other?"

messages_optional = [
    {"role": "user", "content": "In a TIFF file, is the IFD (Image File Directory) optional?"},
    {"role": "assistant", "content": "1.Defintion: In the TIFF (Tagged Image File Format) specification, the Image File Directory (IFD) is a fundamental component that contains metadata about the image, such as image dimensions, color information, and other characteristics. The IFD is a crucial part of the TIFF format and is typically present in TIFF files.\n2.Analysis: According to the TIFF specification, the IFD is not optional. Every TIFF file must contain at least one IFD, and this IFD is referred to as the primary IFD. The primary IFD provides essential information about the image. In some cases, additional IFDs may be present in the TIFF file to describe multiple images or to provide information about specific image tiles or subimages.\n3.Result: Thus, the answer is 'no.' \n"},
    {"role": "user", "content": "In a IFD in a TIFF file, is the TAG optional?"},
    {"role": "assistant", "content": "1.Definition: In the TIFF (Tagged Image File Format) specification, a Tag is a numeric code that represents a specific attribute or property of the image. Each Tag is associated with a data field, and collectively, they form part of the metadata stored in the Image File Directory (IFD). \n2.Analysis: According to the TIFF specification, the presence of certain essential Tags in the IFD is required for a valid TIFF file. These Tags convey crucial information about the image, such as its dimensions, color space, compression method, and more. Therefore, from a compliance standpoint, Tags in the IFD are not considered optional. \n3.Result: Thus, the answer is 'no.' \n"},
    {"role": "user", "content": ""}
]
messages_optional_prompt = "# Based on the above thought process and format, answer the question.\nIn <POS>, is the <TARGET> optional?"

messages_multiple = [
    {"role": "user", "content": "In a TIFF file, is the IFD (Image File Directory) multiple?"},
    {"role": "assistant", "content": "1.Definition: In a TIFF (Tagged Image File Format) file, the Image File Directory (IFD) is a fundamental component that contains metadata about the image, such as image dimensions, color information, and other characteristics. \n2.Analysis: Yes, the presence of multiple IFDs in a TIFF file is allowed. Each IFD can represent distinct images or variations of the same image, providing a hierarchical structure for organizing metadata. \n3.Result: Thus, the answer is 'yes.'\n"},
    {"role": "user", "content": "In a IFD in a TIFF file, is the TAG multiple?"},
    {"role": "assistant", "content": "1.Definition: In a TIFF (Tagged Image File Format) file, a Tag is a numeric code that represents a specific attribute or property of the image. Each Tag is associated with a data field and collectively forms part of the metadata stored in the Image File Directory (IFD). \n2.Analysis: Yes, within an IFD in a TIFF file, multiple Tags can exist. Each Tag represents a different aspect of the image's metadata, such as dimensions, color space, compression method, and more. The combination of multiple Tags in an IFD allows for a comprehensive description of the image. \n3.Result: Thus, the answer is 'yes.'\n"},
    {"role": "user", "content": ""}
]
messages_multiple_prompt = "# Based on the above thought process and format, answer the question.\nIn <POS>, is the <TARGET> multiple?"

import json
import random

def request_openai_api(messages, max_retries = 20, temperature = 0, model = "GPT-3.5"):


    if model == "GPT-3.5":
        # model = "gpt-3.5-turbo-1106"
        model = "gpt-3.5-turbo-0125"
        
        # with open('./config.json', 'r') as file:
        #     data = json.load(file)
        api_keys = data['api_keys']
        api_base = data['api_base']
    elif model == "GPT-4":
        model = "gpt-4-0125-preview"
        model = "gpt-4"
        # with open('./config-4.json', 'r') as file:
        #     data = json.load(file)
        api_keys = data['api_keys']
        api_base = data['api_base']
    else:
        print("Invalid Model")

    start_time = time.time()

    # for key in api_keys:
    attempts = 0
    while attempts < max_retries:
        key = random.choice(api_keys)
        print("key:", key)
        try:
            completion = openai.ChatCompletion.create(
                api_base=api_base,
                model=model,
                messages=messages,
                temperature=temperature,
                api_key=key,
                request_timeout=120
            )
            break
        except Exception as e:
            attempts += 1
            print(e)
            pass

    end_time = time.time()
    request_time = end_time - start_time
    print("---- request time cost:", request_time)

    if not completion:
        return None

    print(completion['usage'])
    output = completion['choices'][0]['message']['content'].strip()
    return output
    
    # if model == "GPT-3.5":
    #     key_manager = KeyManager("./config.json")
    #     model = "gpt-3.5-turbo-1106"
    # elif model == "GPT-4":
    #     key_manager = KeyManager("./config-GPT4.json")
    #     model = "gpt-4-0125-preview"
    # else:
    #     print("Invalid Model")

    # key = key_manager.get_new_key()
    # completion = None  # Initialize the completion variable
    # attempts = 0  # Initialize attempts

    
    # start_time = time.time()
    # while attempts < max_retries:
        
        
    #     try:
    #         completion = openai.ChatCompletion.create(
    #             model=model,
    #             messages=messages,
    #             temperature=temperature,
    #             api_key=key
    #         )
    #         # Attempt to generate a completion
    #         # openai_model.set_key(key)
    #         # completion = openai_model.generate(instruction=prompt.instruction, input=prompt.input, messages=prompt.messages)
    #         # logging.info(f"{LOG_LABEL}key {key} ,request ok")
    #         key_manager.release_key(key)
    #         break
    #     except Exception as e:
    #         # Handle different types of errors
    #         if "exceeded your current quota" in str(e) or "<empty message>" in str(e) or "Limit: 200 / day" in str(e):
    #             # If the quota has been exceeded, remove the key and try again
    #             key_manager.remove_key(key)
    #             key = key_manager.get_new_key()
    #             continue
    #         if "Limit: 3 / min" in str(e) or "Limit: 40000 / min" in str(e):
    #             # If the rate limit is hit, switch the API key and try again
    #             key = key_manager.get_new_key(key)
    #             continue
    #         if "maximum context length" in str(e):
    #             # If the context length is too long, log an error and break the loop
    #             logging.error(f"{LOG_LABEL}Error occurred while accessing openai API: {e}")
    #             break
    #         if "Max retries exceeded with url" in str(e):
    #             # If retries are exceeded, try again
    #             continue
    #         if "That model is currently overloaded with other requests" in str(e):
    #             # If the model is overloaded, try again
    #             continue
    #         if "The server is overloaded" in str(e):
    #             continue
    #         # If an unknown error occurs, log an error and increment the attempt counter
    #         logging.error(
    #                 f"{LOG_LABEL}Unknown error occurred while accessing OpenAI API: {e}. Retry attempt {attempts + 1} "
    #                 f"of "
    #                 f"{max_retries}")
    #         attempts += 1
    #         key = key_manager.get_new_key(key)

    # end_time = time.time()
    # request_time = end_time - start_time
    # print("---- request time cost:", request_time)

    # if not completion:
    #     return None

    # output = completion['choices'][0]['message']['content'].strip()
    # return output

def match_res(text):
  pattern = r"(\d+)\.(.*?):"
  matches = re.findall(pattern, text)

  res = [match[1].strip() for match in matches]
  return res

def extract_res_for_components(raw_llm):
    res = None
    valid = False

    pattern = r"(\d+)\.(.*?):"
    matches = re.findall(pattern, raw_llm)

    res = [match[1].strip() for match in matches]

    if len(res):
        valid = True
        return res, valid
    else:
        res = "Can not find the names of each component using Markdown\'s ordered list syntax, i.e., '1.Component Name'."
        return res, valid

def analyze_structure_optional_msg(file_format):
    prompt = messages_analyze_structure_optional_prompt.replace("<TARGET>", file_format)
    messages = copy.deepcopy(messages_analyze_structure_optional)
    messages[-1]["content"] = prompt

    return messages

def analyze_structure_optional(file_format):
    messages = analyze_structure_optional_msg(file_format)
    res = reask(messages, extract_res_for_components, 5)

    return res

def analyze_structure_necessary_msg(file_format):
    prompt = messages_analyze_structure_necessary_prompt.replace("<TARGET>", file_format)
    messages = copy.deepcopy(messages_analyze_structure_necessary)
    messages[-1]["content"] = prompt

    return messages

def analyze_structure_necessary(file_format):
    messages = analyze_structure_necessary_msg(file_format)
    res = reask(messages, extract_res_for_components, 5)
    
    return res

'''
    目标:给定目标格式,找到所有类型的components
    方法:给定一个"场景/目标",找到与之相关的components。理论上,components越多,能够找到的components类型就越全
'''
def analyze_structure_main(file_format):
    sections_pool = []

    # 1:necessary components
    result = analyze_structure_necessary(file_format)
    print("necessary: ", result)
    if result:
        sections_pool = result + sections_pool

    # 2:optional components
    # result = analyze_structure_optional(file_format)
    # print("optional:", result)
    # if result:
    #     sections_pool = result + sections_pool

    # 3:feature related components

    print(sections_pool)
    return sections_pool

def check_decompose(TARGET, POS):
    if len(POS):
        prompt = messages_decompose_prompt.replace("<TARGET>", TARGET)
        prompt = prompt.replace("<POS>", POS)
    else:
        prompt = messages_decompose_prompt_origin.replace("<TARGET>", TARGET)
    messages = copy.deepcopy(messages_decompose)
    messages[-1]["content"] = prompt
    
    return messages

# def check_decompose_from_size(TARGET, POS):
#     if len(POS):
#         prompt = size_prompt.replace("<TARGET>", TARGET)
#         prompt = prompt.replace("<POS>", POS)
#     else:
#         prompt = size_prompt_origin.replace("<TARGET>", TARGET)
#     messages = copy.deepcopy(messages_decompose)
#     messages[-1]["content"] = prompt

#     output = request_openai_api(messages)
#     print(output)
#     if '**yes**' in output:
#         return False
#     if '**no**' in output:
#         return True

#     if 'yes' in output.lower():
#         return False
#     if 'no' in output.lower():
#         return True
    
#     return False

class Node:
    def __init__(self, name, pos):
        self.name = name
        self.pos = pos

        self.hasChild = -1
        self.children = []

        self.optional = -1
        self.multiple = -1


# {'id':1, 'name':'', 'parent_id':'', 'hasChild': -1, 'children':[], 'optional': -1, 'multiple': -1}
# '0': {'name':'', 'parent_id':-1, 'hasChild': -1, 'children':[], 'optional': -1, 'multiple': -1}
Nodes = {

}

# Nodes = {'0': {'name': 'tiff', 'parent_id': -1, 'hasChild': 1, 'children': ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'], 'optional': -1, 'multiple': -1}, '1': {'name': 'ICC Profile', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '2': {'name': 'Exif Data', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '3': {'name': 'GPS Info', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '4': {'name': 'Thumbnail', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '5': {'name': 'Subfile Type', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '6': {'name': 'Image Description', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '7': {'name': 'Software', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '8': {'name': 'Copyright', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '9': {'name': 'Alpha Channel', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '10': {'name': 'Private or Custom Tags', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '11': {'name': 'Byte Order Mark (BOM)', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '12': {'name': 'Image File Header', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '13': {'name': 'Image File Directory (IFD)', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '14': {'name': 'Image Data', 'parent_id': '0', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}}
# Nodes = {'0': {'name': 'tiff', 'parent_id': -1, 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '1': {'name': 'ICC Profile', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '2': {'name': 'Exif Data', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '3': {'name': 'GPS Info', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '4': {'name': 'Thumbnail', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '5': {'name': 'Alpha Channel', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '6': {'name': 'Private or Custom Tags', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '7': {'name': 'Pixel Data', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '8': {'name': 'Color Space Information', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '9': {'name': 'Bits Per Pixel', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '10': {'name': 'Compression Scheme', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '11': {'name': 'Image Dimensions', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '12': {'name': 'Photometric Interpretation', 'parent_id': '14', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '13': {'name': 'Subfile Type', 'parent_id': '13', 'hasChild': -1, 'children': ['13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25'], 'optional': -1, 'multiple': -1}, '14': {'name': 'Image Width and Image Length', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '15': {'name': 'Bits Per Sample', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '16': {'name': 'Compression', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '17': {'name': 'Photometric Interpretation', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '18': {'name': 'Image Description', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '19': {'name': 'Software', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '20': {'name': 'DateTime', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '21': {'name': 'Artist', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '22': {'name': 'Extra Samples', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '23': {'name': 'Number of Directory Entries', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '24': {'name': 'Directory Entries', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}, '25': {'name': 'Next IFD Pointer (optional)', 'parent_id': '13', 'hasChild': -1, 'children': [], 'optional': -1, 'multiple': -1}}

def find_path(start_id):
    node = Nodes[start_id]
    parents = []
    while node['parent_id'] != -1:
        # print(parents)
        parent_id = node['parent_id']
        node = Nodes[parent_id]

        parents.append(node['name'])
    
    path = " in a ".join(parents)
    # if len(path) and " in a " in path:
    #     path = path[3:]

    return path



def analysis_completed():
    flag = 1
    nextIdx = None

    for id, node in Nodes.items():
        if node['hasChild'] == -1:
            flag = 0
            nextIdx = id

    if flag: # 1 indicates analysis completed, while 0 indicates analysis did not complete
        return 1, -1
    else:
        return 0, nextIdx



def check_decompose_from_size(TARGET, POS):
    if len(POS):
        prompt = size_prompt.replace("<TARGET>", TARGET)
        prompt = prompt.replace("<POS>", POS)
    else:
        prompt = size_prompt_origin.replace("<TARGET>", TARGET)
    messages = copy.deepcopy(messages_decompose_size)
    messages[-1]["content"] = prompt
    
    return messages

def check_decompose_from_specific(TARGET, POS):
    prompt = specific_prompt.replace("<TARGET>", TARGET)
    prompt = prompt.replace("<POS>", POS)

    messages = copy.deepcopy(messages_decompose_specific)
    messages[-1]["content"] = prompt
    
    return messages

def check_decompose_from_num(TARGET, POS):
    prompt = num_prompt.replace("<TARGET>", TARGET)
    prompt = prompt.replace("<POS>", POS)

    messages = copy.deepcopy(messages_decompose_num)
    messages[-1]["content"] = prompt
    
    return messages




def extract_res_for_size(raw_llm):
    res = None
    valid = False

    if '**yes**' in raw_llm.lower():
        valid = True
        res = True
        return res, valid
    elif '**no**' in raw_llm.lower():
        valid = True
        res = False
        return res, valid

    res = 'Can not find **yes/no**'
    return res, valid

def extract_res_for_specific(raw_llm):
    res = None
    valid = False

    if '**yes**' in raw_llm.lower():
        valid = True
        res = True
        return res, valid
    elif '**no**' in raw_llm.lower():
        valid = True
        res = False
        return res, valid

    res = 'Can not find **yes/no**'
    return res, valid

def extract_res_for_num(raw_llm):
    res = None
    valid = False

    if '**yes**' in raw_llm.lower():
        valid = True
        res = True
        return res, valid
    elif '**no**' in raw_llm.lower():
        valid = True
        res = False
        return res, valid

    res = 'Can not find **yes/no**'
    return res, valid


def reask(dialog, extract_res, MAX_TRY, temperature = 0.7):
    SUCCESS = 0
    try_cnt = 0
    while try_cnt < MAX_TRY:
        print("\n* try_cnt:", try_cnt)
        print("** dialog ** [start]")
        for i in range(len(dialog)):
            line = dialog[i]
            role = line["role"]
            content = line["content"]
            print(f"*** {role}: {content}")
        print("** dialog ** [end]")

        raw_llm = request_openai_api(dialog, 20, temperature = temperature)
        # print("raw_llm:", raw_llm)
        res, valid = extract_res(raw_llm) 
        print("** raw_llm:", raw_llm)
        print("** extracted res:", res)

        if valid:
            SUCCESS = 1
            break
        else:
            dialog.append(
                {"role": "assistant", "content": raw_llm}
            )
            dialog.append(
                {"role": "user", "content": res + " Please generate again."}
            )

        try_cnt += 1
    
    if SUCCESS:
        return res
    else:
        print("* Can not finish this task. Here are the unsloved problem:", res)
        return None



def structure_analysis():
    Nodes['0'] = {'name':'tiff', 'parent_id':-1, 'hasChild': -1, 'children':[], 'optional': -1, 'multiple': -1}
    INDEX = 0

    flag, nextIdx = analysis_completed()
    print(flag)
    print(nextIdx)
    while flag == 0:
        print("\n\n======== next round =========\n")
        print("nextIdx:", nextIdx)
        print("name:", Nodes[nextIdx]['name'])

        path = find_path(nextIdx)
        print("path:", path)

        name = Nodes[nextIdx]['name']

        FLAG = 0
        if nextIdx != '0':
            messages = check_decompose_from_specific(name, path)
            concrete = reask(messages, extract_res_for_specific, 5)

            if concrete:

                messages = check_decompose_from_num(name, path)
                is_num = reask(messages, extract_res_for_num, 5)

                if is_num:
                    FLAG = 0
                else:
                    messages = check_decompose(name, path)
                    decompose = reask(messages, extract_res_for_num, 5)

                    if decompose:
                        FLAG = 1
                    else:
                        FLAG = 0
            else:
                FLAG = 0
        else:
            FLAG = 1
        

        if FLAG:
            if nextIdx == '0':
                sections_pool = analyze_structure_main(name)
            else:
                sections_pool = analyze_structure_main(name + " in a " + path)
            print("sections_pool:", sections_pool)

            if name not in sections_pool:            
                Nodes[nextIdx]['hasChild'] = 1
                for section in sections_pool:
                    INDEX += 1
                    Nodes[str(INDEX)] = {'name':section, 'parent_id':nextIdx, 'hasChild': -1, 'children':[], 'optional': -1, 'multiple': -1}
                    Nodes[nextIdx]['children'].append(str(INDEX))
            else:
                print("The analysis may be wrong...")
                Nodes[nextIdx]['hasChild'] = 0
            
        else:
            Nodes[nextIdx]['hasChild'] = 0
        
        flag, nextIdx = analysis_completed()
        print("flag:", flag)
        print("nextIdx:", nextIdx)
        for id, node in Nodes.items():
            print(id)
            print(node)
        

    print(Nodes)

    # res = check_decompose("Directory Entries (Tags)", "an IFD (Image File Directory) in a TIFF file")
    # print(res)


    # file_format =  "Entry Count"  + " in a " + "IFD" + " in a " + "tiff"
    # print(file_format)
    # analyze_structure_main(file_format)














# from mycoverage import mp_executor
# from validate import validate_status
# from util.util import ExecutionStatus

library_need_to_be_installed = []
debug_cnt = {
    "successful": 0,
    "failed": 0
}

messages_feature = [
    {"role": "system", "content": "You are an expert in file structures, familiar with the characteristics and compositions of various file formats."},
    {"role": "user", "content": ""}
]
feature_prompt = """What features can '<TARGET>' files have? Output the information in the following format:

1. <feature 1>: <feature description>
2. <feature 2>: <feature description>
3. <feature 3>: <feature description>
......
N. <feature N>: <feature description>"""
feature_prompt_reask = """Here are some features associated with '<TARGET>' files:
<KNOWN_FEATURES>

Apart from the above features, what other features can '<TARGET>' files have? Output the information in the following format:

1. <feature 1>: <feature description>
2. <feature 2>: <feature description>
3. <feature 3>: <feature description>
......
N. <feature N>: <feature description>"""

messages_code_gen = [
    {"role": "system", "content": "You are an advanced Language Model assistant that can generate, execute, and evaluate code. Please use Markdown syntax to represent code blocks."},
    {"role": "user", "content": ""}
]
code_gen_prompt = """Generate '<TARGET>' files containing the following features using Python without any input files, and save the generated files into `./tmp/`.: 
```
<TARGET_FEATURES>
```
Please use Markdown syntax to represent code blocks. Please ensure that there is only one code block. You don't need to tell me which libraries need to be installed.
"""


feature_prompt_reask_gpt_3_5 = """Apart from the above features, what other features can '<TARGET>' files have? Output the information in the following format:

1. <feature 1>: <feature description>
2. <feature 2>: <feature description>
3. <feature 3>: <feature description>
......
N. <feature N>: <feature description>"""

feature_prompt_reask_gpt_3_5_incre = """
```
<FEATURES>
```

Apart from the above features, what other features can '<TARGET>' files have? Output the information in the following format:

1. <feature 1>: <feature description>
2. <feature 2>: <feature description>
3. <feature 3>: <feature description>
......
N. <feature N>: <feature description>"""

def reask_for_feature(dialog, extract_res, MAX_TRY, model = "GPT-3.5"):
    SUCCESS = 0
    try_cnt = 0
    while try_cnt < MAX_TRY:
        print("\n* try_cnt:", try_cnt)
        print("** dialog ** [start]")
        for i in range(len(dialog)):
            line = dialog[i]
            role = line["role"]
            content = line["content"]
            print(f"*** {role}: {content}")
        print("** dialog ** [end]")

        if model == "GPT-3.5":
            raw_llm = request_openai_api(dialog, 20, temperature = 0.7)
        elif model == "GPT-4":
            raw_llm = request_openai_api(dialog, 5, model = model, temperature = 0.7)
        else:
            print("Invalid Model")
        print("** raw_llm:", raw_llm)
        res, valid = extract_res(raw_llm) 
        print("** extracted res:", res)

        if valid:
            SUCCESS = 1
            break
        else:
            dialog.append(
                {"role": "assistant", "content": raw_llm}
            )
            dialog.append(
                {"role": "user", "content": res + " Please generate again."}
            )

        try_cnt += 1
    
    if SUCCESS:
        res_dict = {}
        for feature in res:
            pattern = r"(\d+)\.(.*?):"
            matches = re.findall(pattern, feature)
            if matches:
                res_dict[matches[0][1].strip()] = feature

        return res_dict, raw_llm
    else:
        print("* Can not finish this task. Here are the unsloved problem:", res)
        return None, raw_llm

def match_res_for_feature(text):
    feature_pool = []
    # feature_head_pool = []
    features_lines = text.strip().split('\n')
    # print("features_lines:", features_lines)
    # print("=== strart ===")
    for line in features_lines:
        # print("\nline:", line)
        pattern = r"(\d+)\.(.*?):"
        matches = re.findall(pattern, line)
        # print(matches)
        

        if matches:
            # print(line)
            # feature_head_pool.append(matches[0][1].strip())
            feature_pool.append(line)
    # print("=== end ===")
    return feature_pool

def extract_res_for_feature(raw_llm):
    feature_pool = match_res_for_feature(raw_llm)

    if feature_pool:
        res = feature_pool
        valid = True
        return res, valid
    else:
        res = """You did not output in the given format. Output the information in the following format:

1. <feature 1>: <feature description>
2. <feature 2>: <feature description>
3. <feature 3>: <feature description>
......
N. <feature N>: <feature description>"""
        valid = False
        return res, valid

def messages_for_feature(TARGET):
    prompt = feature_prompt.replace("<TARGET>", TARGET)

    messages = copy.deepcopy(messages_feature)
    messages[-1]["content"] = prompt
    
    return messages

def messages_for_feature_reask(TARGET, known_features):
    prompt = feature_prompt_reask.replace("<TARGET>", TARGET)
    prompt = prompt.replace("<KNOWN_FEATURES>", known_features)

    messages = copy.deepcopy(messages_feature)
    messages[-1]["content"] = prompt

    # prompt = feature_prompt_reask.replace("<TARGET>", TARGET)
    # messages.append({"role": "user", "content": prompt})
    
    return messages

def messages_for_code_gen(TARGET, TARGET_FEATURES):
    prompt = code_gen_prompt.replace("<TARGET>", TARGET)
    prompt = prompt.replace("<TARGET_FEATURES>", TARGET_FEATURES)

    messages = copy.deepcopy(messages_code_gen)
    messages[-1]["content"] = prompt
    
    return messages



generator_mutation_prompt = """
```
<TARGET_GENERATOR>
```

The code above is used to generate <FROMAT> files. Now, we need to extend this code to generate a new <FROMAT> file that includes an additional `<NEW_FEATURE>` feature besides the existing features. The description of the `<NEW_FEATURE>` feature is as follows:
```
<FEATURE_DES>
```

Please respond according to the following template: 
Here's an extended version of the code that generates a <FROMAT> file with an additional file feature `<NEW_FEATURE>`: 
```
<Generated Code>
```

Please use Markdown syntax to represent code blocks. Please ensure that there is only one code block. You don't need to tell me which libraries need to be installed.
"""

def messages_for_generator_mutation(file_format, feature, feature_description, target_generator_code):
    prompt = generator_mutation_prompt.replace("<FROMAT>", file_format)
    prompt = prompt.replace("<NEW_FEATURE>", feature)
    prompt = prompt.replace("<FEATURE_DES>", feature_description)
    prompt = prompt.replace("<TARGET_GENERATOR>", target_generator_code)

    messages = copy.deepcopy(messages_code_gen)
    messages[-1]["content"] = prompt
    
    return messages

def extract_res_for_code_gen(text):
    res = None
    valid = False

    count = 0
    modified_text = ""
    lines = text.split("\n")
    starts = []
    ends = []
    line_cnt = 0
    for line in lines:
        if line.startswith("```"):
            if count % 2 == 0:
                starts.append(line_cnt)
            else:
                ends.append(line_cnt)
            count += 1
        else:
            modified_text += line + "\n"
        
        line_cnt += 1
    
    if len(starts) == 0 and len(ends) == 0:
        msg = "There is no code block in the input text. Please use Markdown syntax to represent code blocks. Please ensure that there is only one code block."

        res = msg
        valid = False
    elif len(starts) != len(ends):
        msg = "The code blocks in the input text are not conforming to the Markdown syntax."
        
        res = msg
        valid = False
    elif len(starts) > 1:
        msg = "There are several code blocks in the input text. Please ensure that there is only one code block."
        
        res = msg
        valid = False

    if res:
        # did not generate the code block
        return res, valid
    
    res = "\n".join(lines[starts[0]+1:ends[0]])

    if "./tmp/" not in res:
        msg = "You should save the generated files into `./tmp/`."

        res = msg
        valid = False
        return res, valid

    valid = True
    return res, valid

def construct_feature_head_pool(feature_pool):
    feature_head_pool = []
    for feature in feature_pool:
        pattern = r"(\d+)\.(.*?):"
        matches = re.findall(pattern, feature)
        # print(matches)
        

        if matches:
            # print(line)
            feature_head_pool.append(matches[0][1].strip())
    return feature_head_pool

def extract_error_info(error_output):
    global library_need_to_be_installed

    # Extract additional error information, e.g., error line and error function
    # This is a basic example, and you might need to customize it based on your specific error format
    lines = error_output.split('\n')
    last_error_item = None
    error_function = None
    msg = None
    for cnt in range(len(lines)):
        
        line = lines[cnt]
        if "/tmp/tmp" in line.lower():
            # print("Error Line:", line.strip())
            # print("Error Function:", lines[cnt + 1].strip())
            error_function = lines[cnt + 1].strip()

        if 'error' in line.lower():
            last_error_item = line
    # print('Error info:', error_function)

    if error_function:
        msg = "Error Function: " + error_function + "\n"
        if last_error_item:
            msg += "Error Information: " + last_error_item.strip()

            if "ModuleNotFoundError" in last_error_item.strip():
                library_need_to_be_installed.append(last_error_item.strip())

    return msg

def gen_code_debug(dialog, MAX_TRY, model = "GPT-3.5", temperature = 0):

    SUCCESS = 0
    try_cnt = 0
    while try_cnt < MAX_TRY:
        # raw_llm = request_openai_api(dialog, 20)
        if model == "GPT-3.5":
            raw_llm = request_openai_api(dialog, 20, temperature = temperature)
        elif model == "GPT-4":
            raw_llm = request_openai_api(dialog, 5, model = model, temperature = temperature)
        else:
            print("Invalid Model")

        code, msg = extract_res_for_code_gen(raw_llm) 

        if code:
            SUCCESS = 1
            break
        else:
            dialog.append(
                {"role": "assistant", "content": raw_llm}
            )
            dialog.append(
                {"role": "user", "content": msg + " Please generate again."}
            )
            print(msg)

        try_cnt += 1
    
    if SUCCESS:
        return code, raw_llm
    else:
        print("Can not finish this task.")
        return None
    
def display_code(codes):
    codes = codes.split('\n')
    print("++++++++++ code start ++++++++++")
    for line in codes:
        print("+ ", line)
    print("---------- code end ----------")


pip_debug_record = []

def extract_res_for_pip(text):
    res = None
    valid = False

    count = 0
    modified_text = ""
    lines = text.split("\n")
    starts = []
    ends = []
    line_cnt = 0
    for line in lines:
        if line.startswith("```"):
            if count % 2 == 0:
                starts.append(line_cnt)
            else:
                ends.append(line_cnt)
            count += 1
        else:
            modified_text += line + "\n"
        
        line_cnt += 1
    
    if len(starts) == 0 and len(ends) == 0:
        msg = "There is no code block in the input text. Please use Markdown syntax to represent code blocks. Please ensure that there is only one code block."

        res = msg
        valid = False
    elif len(starts) != len(ends):
        msg = "The code blocks in the input text are not conforming to the Markdown syntax."
        
        res = msg
        valid = False
    elif len(starts) > 1:
        msg = "There are several code blocks in the input text. Please ensure that there is only one code block."
        
        res = msg
        valid = False

    if res:
        # did not generate the code block
        return res, valid
    
    res = "\n".join(lines[starts[0]+1:ends[0]])

    if "pip" not in res:
        msg = "You should install the library via pip"

        res = msg
        valid = False
        return res, valid

    valid = True
    return res, valid

def pip_debug_loop(dialog, MAX_TRY):
    SUCCESS = 0
    try_cnt = 0
    while try_cnt < MAX_TRY:
        raw_llm = request_openai_api(dialog, 20)
        code, msg = extract_res_for_pip(raw_llm) 

        if code:
            SUCCESS = 1
            break
        else:
            dialog.append(
                {"role": "assistant", "content": raw_llm}
            )
            dialog.append(
                {"role": "user", "content": msg + " Please generate again."}
            )
            print(msg)

        try_cnt += 1
    
    if SUCCESS:
        return code, raw_llm
    else:
        print("Can not finish this task.")
        return None

def pip_debug(msg, MAX_TRY = 5):
    global pip_debug_record

    install_flag = 0 # 0 represents installing failed, 1 represents installing successfully

    if msg in pip_debug_record: # indicate that has processed this msg before and failed to solved it. If we solved the msg successfully, we should not meet it again.
        return install_flag

    pip_debug_prompt_init = "```\n<MSG>\n```\nPlease use Markdown syntax to represent the command. Please ensure that there is only one command. To solve the above issue using Python's package manager pip, you should run the following command in the command-line interface:"
    pip_debug = [
        {"role": "system", "content": "You are an advanced Language Model assistant that can evaluate, execute, and debug code. Please use Markdown syntax to represent the command."},
    ]

    tmp = copy.deepcopy(pip_debug_prompt_init)
    tmp = tmp.replace('<MSG>', msg)
    pip_debug.append(
        {"role": "user", "content": tmp}
    )
    code, raw_llm = pip_debug_loop(pip_debug, 5)

    # install library via pip
    print("You should install:", code)
    cmd = code.split()
    try:
        subprocess.check_call(cmd, timeout=120)
        install_flag = 1
        print(f"'{cmd}' successfully.")
    except subprocess.CalledProcessError:
        print(f"'{cmd}' failed.")

    pip_debug_record.append(msg)
    return install_flag

def self_debug(code, MAX_TRY, model, temperature = 0.2):
    global debug_cnt

    origin_code = code
    print("* original code:")
    display_code(origin_code)

    user_debug_init = "Fix the bug in the following code, described as '<BUG_DES>'.\n```python\n<CODE>\n```\n\nPlease use Markdown syntax to represent code blocks."
    user_debug = "The repaired code still has the following errors:'<BUG_DES>'"

    

    debug_template = [
        {"role": "system", "content": "You are an advanced Language Model assistant that can evaluate, execute, and debug code. Please use Markdown syntax to represent code blocks."},
    ]
    debug = copy.deepcopy(debug_template)

    
    # print("=== start ===")
    '''
        You can generate programs and execute them
    '''



    SUCCESS = 0
    try_cnt = 0
    while try_cnt < MAX_TRY:
        if try_cnt != 0: # need to reask llm to fix the bug
            print("\n* try_cnt:", try_cnt)
            print("** dialog ** [start]")
            for i in range(len(debug)):
                line = debug[i]
                role = line["role"]
                content = line["content"]
                print(f"*** {role}: {content}")
            print("** dialog ** [end]")

            # print(debug)
            # display(debug)
            code, raw_llm = gen_code_debug(debug, MAX_TRY, model, temperature = temperature)
            print("** repaired code:")
            display_code(code)
        
        if not code:
            break

        status, msg = validate_status_process(code)
        valid = status == ExecutionStatus.SUCCESS


        # Debug Step I: solve the problems of dependency library
        if not valid:
            print("\n=== PIP Start ===")
            msg_tmp = extract_error_info(msg)
            if msg_tmp:
                msg = msg_tmp
            else:
                print("** We can not extract the error info for this msg:")
                print(msg)
                break
            
            library_dependecy_flag = 0
            while True:
                if "ModuleNotFoundError" not in msg:
                    library_dependecy_flag = 1
                    break
                
                flag = pip_debug(msg)
                if flag == 0: # we can not install the corresponding library
                    break
        
                # After install the dependency library, we rerun the program
                status, msg = validate_status_process(code)
                valid = status == ExecutionStatus.SUCCESS

                if valid:
                    library_dependecy_flag = 1
                    break
                else:
                    msg_tmp = extract_error_info(msg)
                    if msg_tmp:
                        msg = msg_tmp
                    else:
                        print("** We can not extract the error info for this msg:")
                        print(msg)
                        break
            if library_dependecy_flag == 0: #indicate that we can not install dependency libraries properly. Thus, we just abort it.
                break
            print("=== PIP End ===\n")


        if valid:
            SUCCESS = 1
            break
        else:
            # msg_tmp = extract_error_info(msg)
            # if msg_tmp:
            #     msg = msg_tmp
            # else:
            #     print("---- We can not extract the error info for this msg:")
            #     print(msg)
            #     break
            print("** final msg:", msg)
            if try_cnt == 0:
                
                tmp = copy.deepcopy(user_debug_init)
                tmp = tmp.replace('<BUG_DES>', msg)
                tmp = tmp.replace('<CODE>', code)

                debug.append(
                    {"role": "user", "content": tmp}
                )
            else:
                debug.append(
                    {"role": "assistant", "content": raw_llm}
                )

                tmp = copy.deepcopy(user_debug)
                tmp = tmp.replace('<BUG_DES>', msg)
                debug.append(
                    {"role": "user", "content": tmp + " Please generate again."}
                )
        try_cnt += 1
    
    if SUCCESS:
        print("* SUCCESS")
        if try_cnt != 0:
            debug_cnt["successful"] += 1
            print("** You have repaired the program successfully!!!")
            # print("\n=== debug start ===")
            # print("--> origin_code:")
            # print(origin_code)
            # print("\n--> current code:")
            # print(code)
            # print("=== debug end ===\n")
        return code
    else:
        debug_cnt["failed"] += 1
        print("* Can not finish this task.")
        return None

def mv_files(source_dir, target_dir, file_prefix):

    # 遍历源目录中的所有文件
    cnt = 1
    for filename in os.listdir(source_dir):
        source_path = os.path.join(source_dir, filename)
        target_path = os.path.join(target_dir, file_prefix + "_" + str(cnt) + os.path.splitext(filename)[1])
        cnt += 1
        
        # # 处理重名问题
        # if os.path.exists(target_path):
        #     base, extension = os.path.splitext(filename)
        #     counter = 1
        #     while True:
        #         new_filename = f"{base}_{counter}{extension}"
        #         new_target_path = os.path.join(target_dir, new_filename)
        #         if not os.path.exists(new_target_path):
        #             target_path = new_target_path
        #             break
        #         counter += 1
        
        # 移动文件
        shutil.move(source_path, target_path)
        print(f"---- Moved {source_path} to {target_path}")

def count_files_in_directory(path):
    count = 0
    for _, _, files in os.walk(path):
        count += len(files)
    return count

def feature_analysis_incre(model, file_format, tmp_path, seeds_path, generators, output_path):

    with open(os.path.join(output_path, "feature_pool.json"), 'r') as file:
        feature_pool = json.load(file)
    
    with open(os.path.join(output_path, "feature_programs.json"), 'r') as file:
        feature_programs = json.load(file)

    tmp = ""
    for feature, feature_des in feature_pool.items():
        tmp += feature_des
        tmp += "\n"
    messages_f = copy.deepcopy(messages_feature)
    tmp_prompt = feature_prompt_reask_gpt_3_5_incre.replace("<TARGET>", file_format)
    messages_f[-1]["content"] = tmp_prompt.replace("<FEATURES>", tmp)
    feature_pool_new, raw_output = reask_for_feature(messages_f, extract_res_for_feature, 3) # feature_pool -> key:feature    value:feature descriptions
    messages_f.append({"role": "assistant", "content": raw_output})

    for feature, description in feature_pool_new.items():
        if feature not in feature_pool.keys():
            feature_pool[feature] = description

    
    try_cnt = 0
    TRY_NUM = 1
    generator_cnt = count_files_in_directory(generators) + 1
    print("++ 2. Analysis loop")
    while try_cnt < TRY_NUM:
        print("++++ 2.1 CUR EPOCH:", try_cnt)

        fail_cnt = 0
        all_cnt = 0
        print("++++++ 2.1.1 feature to generator")
        for feature in list(feature_pool.keys()):
            
            if feature in feature_programs.keys():
                print(">>>>>>>> 2.1.1.1 Has been analyzed:", feature)
                continue
            
            print("++++++++ 2.1.1.1 generate init generator for feature:", feature)

            # feature_description = feature + feature_pool[feature]
            feature_description = feature_pool[feature]
            print("\n>>>>>>>> current feature:", feature_description)

            # generate a generator for each feature
            
            messages_c = messages_for_code_gen(file_format, feature_description)
            generator = reask(messages_c, extract_res_for_code_gen, 3, temperature = 0.7)

            if not generator:
                print(">>>>>>>> We can not generate corrresponding generator for this feature.")
                continue
            
            print("-------- 2.1.1.1 generate init generator for feature:", feature_description)

            # print("---> generator:", generator)

            # execute the generator to get the target file
            # status, msg = validate_status_process(generator)
            # valid = status == ExecutionStatus.SUCCESS
            # print("---> status:", status, "msg:", msg)

            print("++++++++ 2.1.1.2 debug for generator")
            
            generated_code = self_debug(generator, 3, model, temperature = 0.2)
            if generated_code:
                feature_programs[feature] = generated_code
                mv_files(tmp_path, seeds_path, file_format + "-" + str(generator_cnt))

                cur_generator_path = os.path.join(generators, file_format + "-" + str(generator_cnt) + ".py")
                with open(cur_generator_path, 'w') as file:
                    file.write(generated_code) 
                generator_cnt += 1
            else:
                fail_cnt += 1
                print(">>>>>>>> We can not generate the target code for this feature:", feature)
                del feature_pool[feature]

            print("-------- 2.1.1.2 debug for generator")
            
            all_cnt += 1

            

            

        print("------ 2.1.1 feature to generator")

        if fail_cnt == all_cnt:
            print("All items can not generate executable programs -> finsh analysis")
            break
        
        if try_cnt >= TRY_NUM - 1:
            break

        print("++++++ 2.1.2 add more features")
        # try to generate more files
        if model == "GPT-4":
            # GPT-4
            messages_f = messages_for_feature_reask(file_format, str(feature_pool.keys()))
            # print(messages_f)
            feature_pool_new, raw_output = reask_for_feature(messages_f, extract_res_for_feature, 3)
        elif model == "GPT-3.5":
            # GPT-3.5
            tmp_prompt = feature_prompt_reask_gpt_3_5.replace("<TARGET>", file_format)
            messages_f.append({"role": "user", "content": tmp_prompt})
            feature_pool_new, raw_output = reask_for_feature(messages_f, extract_res_for_feature, 3)
            messages_f.append({"role": "assistant", "content": raw_output})
        
        print("------ 2.1.2 add more features")

        print("++++++ 2.1.3 show added features")
        if not feature_pool_new:
            print(">>>>>> Can not continue analysis")
            break

        repeat_cnt = 0
        for feature, description in feature_pool_new.items():
            if feature not in feature_pool.keys():
                feature_pool[feature] = description
            else:
                repeat_cnt += 1
                print("-", feature, "has existed")
        
        print(">>>>>> repeat_cnt:", repeat_cnt)
        print(">>>>>> new feature_head_pool:", feature_pool.keys())
        
        if repeat_cnt == len(feature_pool_new):
            print(">>>>>> All items are repeated -> finsh analysis")
            break
        
        print("------ 2.1.3 show added features")

        try_cnt += 1

        print("---- 2.2 CUR EPOCH:", try_cnt)

    

    for feature, description in feature_pool.items():
        print(">> ", feature, ":", description)
    
    print("-- 2. Analysis loop")

    with open(os.path.join(output_path, "feature_pool.json"), 'w') as file:
        json.dump(feature_pool, file)
    
    with open(os.path.join(output_path, "feature_programs.json"), 'w') as file:
        json.dump(feature_programs, file)

def count_files_in_directory(path):
    count = 0
    for _, _, files in os.walk(path):
        count += len(files)
    return count

def feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, TRY_NUM):

    feature_programs = {} # key:feature    value:corresponding program
    print("++ 1. Get init features")
    messages_f = messages_for_feature(file_format)
    feature_pool, raw_output = reask_for_feature(messages_f, extract_res_for_feature, 3) # feature_pool -> key:feature    value:feature descriptions
    messages_f.append({"role": "assistant", "content": raw_output})

    if not feature_pool:
        print(">> We failed to analyze the features for the given file format.")
        return 1
    print(">> init feature_head_pool:", feature_pool.keys())
    print("-- 1. Get init features")


    retry_cnt = 0
    try_cnt = 0
    generator_cnt = 1
    last_gen_cnt = count_files_in_directory(generators)
    print("++ 2. Analysis loop")
    while try_cnt < TRY_NUM:
        print("++++ 2.1 CUR EPOCH:", try_cnt)
        # print("\n========== EPOCH:", try_cnt, " ==========\n")
        # print("-- current feature_pool:", feature_pool)

        fail_cnt = 0
        all_cnt = 0
        print("++++++ 2.1.1 feature to generator")
        for feature in list(feature_pool.keys()):
            if feature in feature_programs.keys():
                print(">>>>>>>> 2.1.1.1 Has been analyzed:", feature)
                continue
            
            

            # feature_description = feature + feature_pool[feature]
            feature_description = feature_pool[feature]
            print("\n>>>>>>>> current feature:", feature_description)

            # generate a generator for each feature
            
            feature_try_cnt = 0
            while feature_try_cnt < 3:
                print(">>>>>>>> feature_try_cnt:", feature_try_cnt)
                print("++++++++ 2.1.1.1 generate init generator for feature:", feature)
                if try_cnt == 0:
                    messages_c = messages_for_code_gen(file_format, feature_description)
                else:
                    # get a generator
                    generator_list = [f for f in os.listdir(generators) if os.path.isfile(os.path.join(generators, f))]
                    if len(generator_list) == 0:
                        messages_c = messages_for_code_gen(file_format, feature_description)
                    else:
                        target_generator = random.choice(generator_list)
                        target_generator_path = os.path.join(generators, target_generator)
                        print("Selected Generator:", target_generator_path)
                        with open(target_generator_path, 'r') as file:
                            target_generator_code = file.read()

                        messages_c = messages_for_generator_mutation(file_format, feature, feature_description, target_generator_code)
                generator = reask(messages_c, extract_res_for_code_gen, 3, temperature = 0.7)

                if not generator:
                    feature_try_cnt += 1
                    print(">>>>>>>> We can not generate corrresponding generator for this feature.")
                    continue
                
                print("-------- 2.1.1.1 generate init generator for feature:", feature_description)

                # print("---> generator:", generator)

                # execute the generator to get the target file
                # status, msg = validate_status_process(generator)
                # valid = status == ExecutionStatus.SUCCESS
                # print("---> status:", status, "msg:", msg)

                print("++++++++ 2.1.1.2 debug for generator")
                
                generated_code = self_debug(generator, 3, model, temperature = 0.2)
                if generated_code:
                    feature_programs[feature] = generated_code
                    mv_files(tmp_path, seeds_path, file_format + "-" + str(generator_cnt))

                    cur_generator_path = os.path.join(generators, file_format + "-" + str(generator_cnt) + ".py")
                    with open(cur_generator_path, 'w') as file:
                        file.write(generated_code) 
                    generator_cnt += 1

                    break                    
                
                feature_try_cnt += 1

                print("-------- 2.1.1.2 debug for generator")
            
            if feature_try_cnt == 3:
                fail_cnt += 1
                print(">>>>>>>> We can not generate the target code for this feature:", feature)
                del feature_pool[feature]

            
            all_cnt += 1

        print("------ 2.1.1 feature to generator")

        # if fail_cnt == all_cnt:
        #     print("All items can not generate executable programs -> finsh analysis")
        #     break
        
        if try_cnt >= TRY_NUM - 1:
            break

        print("++++++ 2.1.2 add more features")
        # try to generate more files
        if model == "GPT-4":
            # GPT-4
            messages_f = messages_for_feature_reask(file_format, str(feature_pool.keys()))
            # print(messages_f)
            feature_pool_new, raw_output = reask_for_feature(messages_f, extract_res_for_feature, 3)
        elif model == "GPT-3.5":
            # GPT-3.5
            tmp_prompt = feature_prompt_reask_gpt_3_5.replace("<TARGET>", file_format)
            messages_f.append({"role": "user", "content": tmp_prompt})
            feature_pool_new, raw_output = reask_for_feature(messages_f, extract_res_for_feature, 3)
            messages_f.append({"role": "assistant", "content": raw_output})
            # print("\n-----")
            # print(messages_f)
            # print("-----\n")
        
        print("------ 2.1.2 add more features")

        # filter the repeated items in the feature_pool_new
        # feature_head_pool = construct_feature_head_pool(feature_pool)
        # feature_head_pool_new = construct_feature_head_pool(feature_pool_new)
        # print("feature_head_pool:", feature_pool.keys())
        print("++++++ 2.1.3 show added features")
        if not feature_pool_new:
            print(">>>>>> Can not continue analysis")
            break
        # print(">>>>>> feature_head_pool_new:", feature_pool_new.keys())

        repeat_cnt = 0
        for feature, description in feature_pool_new.items():
            if feature not in feature_pool.keys():
                feature_pool[feature] = description
            else:
                repeat_cnt += 1
                print("-", feature, "has existed")
        
        print(">>>>>> repeat_cnt:", repeat_cnt)
        print(">>>>>> new feature_head_pool:", feature_pool.keys())
        
        if repeat_cnt == len(feature_pool_new):
            print(">>>>>> All items are repeated -> finsh analysis")
            break
        
        print("------ 2.1.3 show added features")

        if count_files_in_directory(generators) > last_gen_cnt:
            retry_cnt = 0
            try_cnt += 1
            last_gen_cnt = count_files_in_directory(generators)
        else:
            retry_cnt += 1
            if retry_cnt > 3:
                break
            print("CURRENT EPOCH CAN NOT GET ANY NEW GENERATORS.")

        print("---- 2.2 CUR EPOCH:", try_cnt)

    

    for feature, description in feature_pool.items():
        print(">> ", feature, ":", description)
    
    print("-- 2. Analysis loop")

    with open(os.path.join(output_path, "feature_pool.json"), 'w') as file:
        json.dump(feature_pool, file)
    
    with open(os.path.join(output_path, "feature_programs.json"), 'w') as file:
        json.dump(feature_programs, file)


from collections import Counter
def get_file_format(seeds_list):
    seeds_list = [s for s in seeds_list if s.count('.') == 1]
    file_extensions = [file_name.split('.')[-1] for file_name in seeds_list]
    extension_counts = Counter(file_extensions)
    max_extensions = extension_counts.most_common(6)
    extension_names = [extension[0] for extension in max_extensions]
    return extension_names


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Description of your script.')
    parser.add_argument('--output', type=str, help='The path to store the output')
    parser.add_argument('--program', type=str, help='The target program')
    parser.add_argument('--input', type=str, help='The initial seeds path')
    parser.add_argument('--mode', type=str, help='The mode to get the generators')
    parser.add_argument('--formatGet', type=str, default="predefined", help='The mode to get the file format: auto/predefined')
    args = parser.parse_args()

    output_path = args.output

    model = "GPT-3.5"
    tmp_path = "./tmp" # can not be changed
    if not os.path.exists(tmp_path):
        os.makedirs(tmp_path)

    if args.mode == "init":
        if not os.path.exists(output_path):
            print(f"There is no {output_path}.")
            exit(0)

        
    elif args.mode == "incre":
        if not os.path.exists(output_path):
            print("There is no output.")
            exit(0)
    else:
        print("Get invalid mode setting.")
        exit(0)

    seeds_path = os.path.join(args.output, "gen_seeds")
    generators = os.path.join(args.output, "generators")
    if not os.path.exists(seeds_path):
        os.makedirs(seeds_path)
    if not os.path.exists(generators):
        os.makedirs(generators)

    start_time = time.time()

    if args.formatGet == "auto":
        print("=== Get file format: auto ===")
        seeds_list = os.listdir(args.input)
        file_formats = get_file_format(seeds_list)
        print("$$$$$$$$$$$$$$$$$$$$$$$$$$")
        print("target file formats:", file_formats)
        print("$$$$$$$$$$$$$$$$$$$$$$$$$$")
        if not file_formats:
            file_formats = program_to_format[args.program]
    else:
        print("=== Get file format: predefined ===")
        file_formats = program_to_format[args.program]

    for file_format in file_formats:
        print("\n\n\n\n\n***************************")
        print("************", file_format , "************")
        print("***************************")
        try:
            if args.mode == "init":
                print("\n\n\n\n\n=============== INIT ================")
                if len(file_formats) == 1:
                    feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, 3) 
                else:
                    feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, 1) 
            elif args.mode == "incre":
                print("\n\n\n\n\n=============== INCRE ================")
                feature_analysis_incre(model, file_format, tmp_path, seeds_path, generators, output_path) 
            else:
                print("Get invalid mode setting.")
                exit(0)
        except KeyboardInterrupt:
            print("You need install the following library to improve the fuzzing performance")
            for l in library_need_to_be_installed:
                print(l)




    if len(library_need_to_be_installed):
        print("You need install the following library to improve the fuzzing performance")
        for l in library_need_to_be_installed:
            print(l)

    # runtime
    end_time = time.time()
    run_time = end_time - start_time
    print("run_time: ", run_time)
    print("successful debug:", debug_cnt["successful"])
    print("failed debug:", debug_cnt["failed"])

    file_count = 0
    for _, _, files in os.walk(seeds_path):
        file_count += len(files)
    print("generated seeds num:", file_count)