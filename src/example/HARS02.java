package example;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.bouncycastle.crypto.CipherParameters;
import org.junit.Test;
import org.junit.runners.Parameterized;

import static org.junit.Assert.assertFalse;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import tool.Stopwatch;
public class HARS02  {
	
	public static final String PUBLICKEY1="pubicKey1";
	public static final String SECRETKEY1="secretKey1";
	public static final String PUBLICKEY2="pubicKey2";
	public static final String SECRETKEY2="secretKey2";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g1;	
	private Element g2;
			
	public static Collection parameters() {
		Object[][] data = {
				{false, "pairing/a/a_181_603.properties"},
				{true, "pairing/a/a_181_603.properties"},
		};
		PairingFactory.getInstance().setReuseInstance(false);
		return Arrays.asList(data);
	}

	public HARS02(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g1 = pairing.getG1().newRandomElement().getImmutable();	
		g2 = pairing.getG2().newRandomElement().getImmutable();
		print("g1",g1);
		print("g2",g2);
		
	}
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);
		
		//生成密钥x
		Element x1 = pairing.getZr().newRandomElement();		
		Element x2 = pairing.getZr().newRandomElement();
		//生成公钥pk
		Element pk1 = g2.duplicate().powZn(x1); // We need to duplicate g because it's a system parameter.
		Element pk2 = g2.duplicate().powZn(x2);
		keyMap.put(SECRETKEY1, x1);
		keyMap.put(PUBLICKEY1, pk1);
		keyMap.put(SECRETKEY2, x2);
		keyMap.put(PUBLICKEY2, pk2);
		return keyMap;
		
	}
	/**
	 * 
	 * @param id 块的编号
	 * @param m  块的信息
	 * @param secretKey
	 * @return
	 */
	public Map<String,Element> signs(String id,String message, Element secretKey1,Element pk2 ){
	    Map<String,Element> signatures=new HashMap<String,Element>(2);
		//将信息的哈希值映射为G1中的元素h
		byte[] hash = id.getBytes(); // Generate an hash from m (48-bit hash)
		byte[] mbytes = message.getBytes();
		Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);
		Element h_ = pairing.getG1().newElementFromHash(hash, 0, hash.length);
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element a = pairing.getZr().newElement();
		Element σ2 =g1.duplicate().powZn(a);
		Element β=h.mul(g1.powZn(m));
		
		Element t=β.div((pk2.powZn(a)));
		Element σ1=t.powZn(secretKey1.invert());//对消息的签名为sig
		//Element σ=β.powZn(secretKey.invert());
		print("h",h);
		print("h-",h);
		print("β",β);
		print("σ1",σ1);
		print("σ2",σ2);
		signatures.put("sig1", σ1);
		signatures.put("sig2", σ2);
		return signatures;
	}
	public boolean proofVerify(Element pk1,Element pk2, String id, String message,Element sig1,Element sig2){
		
		//再次映射m的哈希值
		byte[] hash = id.getBytes(); // Generate an hash from m (48-bit hash)
		byte[] mbytes=message.getBytes();
		Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element β=h.mul(g1.duplicate().powZn(m));
		
		// 验证签名有效性
		Element temp1 = pairing.pairing(β, g2);
		Element temp2 = pairing.pairing(sig1, pk1);
		Element temp3 = pairing.pairing(sig2, pk2);
		return temp1.equals(temp2.mul(temp3))? true :false;
	}
	public static void print(String s,Object o){
		System.out.println(s+"="+o);
	}
	public static void main (String [] args) throws Exception{
		//List alist=new ArrayList(BlsDSA.parameters());
	
		//BlsDSA bls=new BlsDSA(false, "pairing/a/a_181_603.properties");
		HARS02 bls=new HARS02(false, "pairing/e/e.properties");
		
		Stopwatch start=new  Stopwatch();
		bls.setup();		
		Map<String,Element> keyMap=bls.keyGen();
		 String message="abcde";
		 String id="12";
		 
		Map<String ,Element> signatures=bls.signs(id,message,keyMap.get(SECRETKEY1),keyMap.get(PUBLICKEY2));	
		
		assertTrue(bls.proofVerify(keyMap.get(PUBLICKEY1),keyMap.get(PUBLICKEY2),id,message,signatures.get("sig1"),signatures.get("sig2")));
		assertFalse(bls.proofVerify(keyMap.get(PUBLICKEY1),keyMap.get(PUBLICKEY2),id,message,signatures.get("sig1"),signatures.get("sig2")));
		System.out.println(start.elapsedTime());
	}

}

