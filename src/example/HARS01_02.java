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
import tool.Accumulator;
import tool.Stopwatch;
public class HARS01_02  {
	
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
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

	public HARS01_02(boolean usePBC, String curvePath) {
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
		
		//������Կx
		Element x = pairing.getZr().newRandomElement();
		System.out.println("x="+x);
		
		//���ɹ�Կpk
		Element pk = g2.powZn(x); // We need to duplicate g because it's a system parameter.
		System.out.println("pk="+pk);
		keyMap.put(SECRETKEY, x);
		keyMap.put(PUBLICKEY, pk);
		print("keysize=",pk.getLengthInBytes());
		return keyMap;
		
	}
	/**
	 * 
	 * @param id ��ı��
	 * @param m  �����Ϣ
	 * @param secretKey
	 * @return
	 */
	public Element sign(String id,String message, Element secretKey){
	
		//����Ϣ�Ĺ�ϣֵӳ��ΪG1�е�Ԫ��h
		byte[] hash = id.getBytes(); 		
		byte[] mbytes = message.getBytes();		
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element h = pairing.getZr().newElementFromHash(hash, 0, hash.length);		
		Element ��=(g2.powZn(h.mulZn(m)));
		
		//f:g1->g2 ???????�ѵ�ֻ��һ�ֱ�ʾ����
		Element ��=(��.mulZn((secretKey.invert())));//����Ϣ��ǩ��Ϊsig
		print("h",h);		
		print("m",m);
		print("��",��);
		print("��",��);		
		
		return ��;
	}
	public boolean proofVerify(Element pk, String id, String message,Element sig)throws Exception{
		
		//�ٴ�ӳ��m�Ĺ�ϣֵ
		byte[] hash = id.getBytes(); // Generate an hash from m (48-bit hash)
		byte[] mbytes=message.getBytes();
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element h = pairing.getZr().newElementFromHash(hash, 0, hash.length);
		Element _��=g2.powZn(h.mulZn(m));
				
		print("_m=",m);
		print("_h=",h);
		print("_��=",_��);
		
		// ��֤ǩ����Ч��
		Element temp1 = pairing.pairing(_��, g2);
		Element temp2 = pairing.pairing(sig, pk);
		return temp1.equals(temp2)? true :false;
	}
	public static void print(String s,Object o){
		System.out.println(s+"="+o);
	}
	public static void main (String [] args) throws Exception{
		Accumulator acc=new Accumulator();
		for(int i=0;i<10;i++){			
			
			HARS01_02 bls=new HARS01_02(false, "pairing/d/d_9563.properties");
		
		Stopwatch start=new  Stopwatch();
		bls.setup();		
		Map<String,Element> keyMap=bls.keyGen();
		 String message="abcde";
		 String id="12";
		 
		Element sig=bls.sign(id,message,keyMap.get(SECRETKEY));		
		//boolean right=bls.proofVerify(keyMap.get(PUBLICKEY),id,message,sig);
		
		assertTrue(bls.proofVerify(keyMap.get(PUBLICKEY),id,message,sig));		
		assertFalse(bls.proofVerify(keyMap.get(PUBLICKEY),id,message+"false",sig));
		
		acc.addDataValue(start.elapsedTime());
		}
		System.out.println(acc.mean());
	}

}
