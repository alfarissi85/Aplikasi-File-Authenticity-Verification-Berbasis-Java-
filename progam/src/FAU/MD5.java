
package FAU;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Arrays;


public class MD5 {
    public static String md5DigestHexString(String message) {
        int[] s = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
                20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15,
                21, 6, 10, 15, 21, 6, 10, 15, 21 };

        int[] K = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

        int a0 = 0x67452301; // A
        int b0 = 0xefcdab89; // B
        int c0 = 0x98badcfe; // C
        int d0 = 0x10325476; // D


        byte[] msgInBytes = message.getBytes();

        int tempMsgTotalNbOfBytes = msgInBytes.length + 1 + 8;
        int modOfMsgInBytes = tempMsgTotalNbOfBytes % 64;

        int nbOfZeroBytesNeeded = 0;
        if (modOfMsgInBytes > 0)
            nbOfZeroBytesNeeded = 64 - modOfMsgInBytes;

        tempMsgTotalNbOfBytes += nbOfZeroBytesNeeded;

        byte[] finalTabForMsgInBytesToDigest = Arrays.copyOf(msgInBytes, tempMsgTotalNbOfBytes);

        finalTabForMsgInBytesToDigest[msgInBytes.length] = (byte) 128;

        long msgLengthInBits = (long) msgInBytes.length * 8;
        for (int i = 0; i < 8; i++) {

            finalTabForMsgInBytesToDigest[tempMsgTotalNbOfBytes - 8 + i] = (byte) msgLengthInBits;

            msgLengthInBits >>>= 8;
        }

        for (int i = 0; i < finalTabForMsgInBytesToDigest.length; i += 64) {
            int A = a0;
            int B = b0;
            int C = c0;
            int D = d0;
            int F = 0, g = 0;

            for (int j = 0; j < 64; j++) {
                if (j <= 15) {
                    F = (B & C) | ((~B) & D);
                    g = j;
                } else if (j <= 31) {
                    F = (D & B) | ((~D) & C);
                    g = (5 * j + 1) % 16;
                } else if (j <= 47) {
                    F = B ^ C ^ D;
                    g = (3 * j + 5) % 16;
                } else if (j <= 63) {
                    F = C ^ (B | (~D));
                    g = (7 * j) % 16;
                }
                IntBuffer intBuf = ByteBuffer.wrap(finalTabForMsgInBytesToDigest).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
                int[] array = new int[16];  // We're storing 16 integers each iteration.
                intBuf.get(new int[i / 4]); // Skip integers that we've already used.
                intBuf.get(array);          // Get the next 16 integers.
                int chunk = array[g];       // Save the chunk.

                F = F + A + K[j] + chunk;
                A = D;
                D = C;
                C = B;
                B = B + Integer.rotateLeft(F, s[j]);
            }

            a0 = a0 + A;
            b0 = b0 + B;
            c0 = c0 + C;
            d0 = d0 + D;
        }
        byte[] md5 = new byte[16];
        int count = 0;
        for (int k = 0; k < 4; k++) {
            int n = (k == 0) ? a0 : ((k == 1) ? b0 : ((k == 2) ? c0 : d0));
            for (int j = 0; j < 4; j++) {
                md5[count] = (byte) n;
                count++;
                n >>>= 8;
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int l = 0; l < md5.length; l++) {
            sb.append(String.format("%02X", md5[l] & 0xFF));
        }
        return sb.toString().toLowerCase();
    }
}
