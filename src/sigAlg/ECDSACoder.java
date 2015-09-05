package sigAlg;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * ECDSA��ȫ�������
 * 
 * @author ����
 * @version 1.0
 * @since 1.0
 */
public abstract class ECDSACoder {

	/**
	 * ����ǩ�� ��Կ�㷨
	 */
	private static final String KEY_ALGORITHM = "ECDSA";

	/**
	 * ����ǩ�� ǩ��/��֤�㷨
	 * 
	 * Bouncy Castle֧������7���㷨
	 * NONEwithECDSA 
	 * RIPEMD160withECDSA 
	 * SHA1withECDSA
	 * SHA224withECDSA 
	 * SHA256withECDSA 
	 * SHA384withECDSA 
	 * SHA512withECDSA
	 */
	private static final String SIGNATURE_ALGORITHM = "SHA1withECDSA";

	/**
	 * ��Կ
	 */
	private static final String PUBLIC_KEY = "ECDSAPublicKey";

	/**
	 * ˽Կ
	 */
	private static final String PRIVATE_KEY = "ECDSAPrivateKey";

	/**
	 * ��ʼ����Կ
	 * 
	 * @return Map ��ԿMap
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception {

		// ����BouncyCastleProvider֧��
		Security.addProvider(new BouncyCastleProvider());

		BigInteger p = new BigInteger(
				"883423532389192164791648750360308885314476597252960362792450860609699839");
 
		ECFieldFp ecFieldFp = new ECFieldFp(p);

		BigInteger a = new BigInteger(
				"7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
				16);
 
		BigInteger b = new BigInteger(
				"6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
				16);
 
		EllipticCurve ellipticCurve = new EllipticCurve(ecFieldFp, a, b);

		BigInteger x = new BigInteger(
				"110282003749548856476348533541186204577905061504881242240149511594420911");
 
		BigInteger y = new BigInteger(
				"869078407435509378747351873793058868500210384946040694651368759217025454");
 
		ECPoint g = new ECPoint(x, y);

		BigInteger n = new BigInteger(
				"883423532389192164791648750360308884807550341691627752275345424702807307");

		ECParameterSpec ecParameterSpec = new ECParameterSpec(ellipticCurve, g,
				n, 1);

		// ʵ������Կ�Զ�������
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);

		// ��ʼ����Կ�Զ�������
		kpg.initialize(ecParameterSpec, new SecureRandom());

		// ������Կ�Զ�
		KeyPair keypair = kpg.generateKeyPair();

		ECPublicKey publicKey = (ECPublicKey) keypair.getPublic();

		ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();

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

		// ����BouncyCastleProvider֧��
		Security.addProvider(new BouncyCastleProvider());

		// ת��˽Կ����
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);

		// ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// ȡ˽Կ�׶���
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
	 * @return boolean У��ɹ�����true ʧ�ܷ���false
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign)
			throws Exception {

		// ����BouncyCastleProvider֧��
		Security.addProvider(new BouncyCastleProvider());

		// ת����Կ����
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);

		// ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// ���ɹ�Կ
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
}
