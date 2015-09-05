package baseModel;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;



import org.bouncycastle.crypto.CipherParameters;
import org.junit.Test;
import org.junit.runners.Parameterized;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import tool.Stopwatch;
public class BLS  {
	
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g;	
			
	public static Collection parameters() {
		Object[][] data = {
				{false, "pairing/a/a_181_603.properties"},
				{true, "pairing/a/a_181_603.properties"},
		};
		PairingFactory.getInstance().setReuseInstance(false);
		return Arrays.asList(data);
	}

	public BLS(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g = pairing.getG1().newRandomElement();	
		System.out.println("g="+g);
	}
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);
		
		//生成密钥x
		Element x = pairing.getZr().newRandomElement();
		System.out.println("x="+x);
		
		//生成公钥pk
		Element pk = g.duplicate().powZn(x); // We need to duplicate g because it's a system parameter.
		System.out.println("pk="+pk);
		keyMap.put(SECRETKEY, x);
		keyMap.put(PUBLICKEY, pk);
		return keyMap;
		
	}
	public Element sign(String message, Element secretKey){
	
		//将信息的哈希值映射为G1中的元素h
		byte[] hash = message.getBytes(); // Generate an hash from m (48-bit hash)
		Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);
		System.out.println("h="+h);
		
		//对消息的签名为sig
		Element sig = h.powZn(secretKey); // We can discard the value h, so we don't need to duplicate it.
		System.out.println("sig="+sig);
		return sig;
	}
	public boolean verify(Element pk, String message, String identity,Element sig){
		
		//再次映射m的哈希值
		byte[] hash = message.getBytes(); // Generate an hash from m (48-bit hash)
		Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);

		System.out.println("h="+h);
		
		// 验证签名有效性
		Element temp1 = pairing.pairing(g, sig);
		Element temp2 = pairing.pairing(pk, h);
		return temp1.equals(temp2)? true :false;
	}
		
	public static void main (String [] args) throws Exception{
		
		BLS bls=new BLS(false, "pairing/e/e.properties");
		
		Stopwatch start=new  Stopwatch();
		bls.setup();		
		Map<String,Element> keyMap=bls.keyGen();
		 String message="abcde";
		Element sig=bls.sign(message,keyMap.get(SECRETKEY));
		//System.out.println(sig);
		boolean result;
		result=bls.verify(keyMap.get(PUBLICKEY),message,"",sig);
		
		System.out.println(result);
		System.out.println(start.elapsedTime());
	}

}
