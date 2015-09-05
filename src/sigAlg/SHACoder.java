package sigAlg;

import java.security.MessageDigest; 

/**
 * SHA�������
 * 
 * @author ����
 * @version 1.0
 * @since 1.0
 */
public abstract class SHACoder {

	/**
	 * SHA-1����
	 * 
	 * @param data
	 *            ����������
	 * @return byte[] ��ϢժҪ
	 * 
	 * @throws Exception
	 */
	public static byte[] encodeSHA(byte[] data) throws Exception {
		// ��ʼ��MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA");

		// ִ����ϢժҪ
		return md.digest(data);
	}


	/**
	 * SHA-256����
	 * 
	 * @param data
	 *            ����������
	 * @return byte[] ��ϢժҪ
	 * 
	 * @throws Exception
	 */
	public static byte[] encodeSHA256(byte[] data) throws Exception {
		// ��ʼ��MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		// ִ����ϢժҪ
		return md.digest(data);
	}

	/**
	 * SHA-384����
	 * 
	 * @param data
	 *            ����������
	 * @return byte[] ��ϢժҪ
	 * 
	 * @throws Exception
	 */
	public static byte[] encodeSHA384(byte[] data) throws Exception {
		// ��ʼ��MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA-384");

		// ִ����ϢժҪ
		return md.digest(data);
	}

	/**
	 * SHA-512����
	 * 
	 * @param data
	 *            ����������
	 * @return byte[] ��ϢժҪ
	 * 
	 * @throws Exception
	 */
	public static byte[] encodeSHA512(byte[] data) throws Exception {
		// ��ʼ��MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA-512");

		// ִ����ϢժҪ
		return md.digest(data);
	}
}
