package sigAlg;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * DSA��ȫ�������
 * 
 * @author ����
 * @version 1.0
 */
public abstract class DSACoder {

	/**
	 * ����ǩ����Կ�㷨
	 */
	public static final String ALGORITHM = "DSA";

	/**
	 * ����ǩ��
	 * ǩ��/��֤�㷨
	 */
	public static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
	
	/**
	 * ��Կ
	 */
	private static final String PUBLIC_KEY = "DSAPublicKey";

	/**
	 * ˽Կ
	 */
	private static final String PRIVATE_KEY = "DSAPrivateKey";
	
	/**
	 * DSA��Կ���� 
	 * Ĭ��1024λ�� 
	 * ��Կ���ȱ�����64�ı����� 
	 * ��Χ��512��1024λ֮�䣨����
	 */
	private static final int KEY_SIZE = 1024;
	
	/**
	 * ǩ��
	 * 
	 * @param data
	 *            ��ǩ������
	 * @param privateKey
	 *            ˽Կ
	 * @return byte[] ����ǩ��
	 * @throws Exception
	 */
	public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {

		// ��ԭ˽Կ
		// ת��˽Կ����
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);

		// ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

		// ����˽Կ����
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// ʵ����Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);

		// ��ʼ��Signature
		signature.initSign(priKey);

		// ����
		signature.update(data);

		// ǩ��
		return signature.sign();
	}

	/**
	 * У��
	 * 
	 * @param data
	 *            ��У������
	 * @param publicKey
	 *            ��Կ
	 * @param sign
	 *            ����ǩ��
	 * 
	 * @return boolean У��ɹ�����true ʧ�ܷ���false
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign)
			throws Exception {

		// ��ԭ��Կ
		// ת����Կ����
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);

		// ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

		// ȡ��Կ�׶���
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		// ʵ����Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);

		// ��ʼ��Signature
		signature.initVerify(pubKey);

		// ����
		signature.update(data);

		// ��֤
		return signature.verify(sign);
	}

	/**
	 * ������Կ
	 * 
	 * @return ��Կ����
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception {

		// ��ʼ����Կ�Զ�������
		KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);

		// ʵ������Կ�Զ�������
		keygen.initialize(KEY_SIZE, new SecureRandom());

		// ʵ������Կ�Զ�
		KeyPair keys = keygen.genKeyPair();

		DSAPublicKey publicKey = (DSAPublicKey) keys.getPublic();

		DSAPrivateKey privateKey = (DSAPrivateKey) keys.getPrivate();

		// ��װ��Կ
		Map<String, Object> map = new HashMap<String, Object>(2);

		map.put(PUBLIC_KEY, publicKey);
		map.put(PRIVATE_KEY, privateKey);

		return map;
	}

	/**
	 * ȡ��˽Կ
	 * 
	 * @param keyMap
	 *            ��ԿMap
	 * @return byte[] ˽Կ
	 * @throws Exception
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap)
			throws Exception {

		Key key = (Key) keyMap.get(PRIVATE_KEY);

		return key.getEncoded();
	}

	/**
	 * ȡ�ù�Կ
	 * 
	 * @param keyMap
	 *            ��ԿMap
	 * @return byte[] ��Կ
	 * @throws Exception
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap)
			throws Exception {

		Key key = (Key) keyMap.get(PUBLIC_KEY);

		return key.getEncoded();
	}
}
