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
import java.util.Random;


import org.bouncycastle.crypto.CipherParameters;
import org.junit.Test;
import org.junit.runners.Parameterized;

import static org.junit.Assert.assertFalse;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import tool.Stopwatch;
public class ECCBM2 {	
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g1;	
	private Element g2;	
	private ElementPowPreProcessing g2Pre;
	private Element gT;
			
	public static Collection parameters() {
		Object[][] data = {
				{false, "pairing/a/a_181_603.properties"},
				{true, "pairing/d/d_9563.properties"},
		};
		PairingFactory.getInstance().setReuseInstance(false);
		return Arrays.asList(data);
	}

	public ECCBM2(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g1 = pairing.getG1().newRandomElement().getImmutable();
		g2 = pairing.getG2().newRandomElement().getImmutable();	
		Element g3 = pairing.getG2().newElement(g2);
		println(g2);
		println(g3);
	}
	/**
	 * 
	 * @return
	 */
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);
		
		//������Կx
		Element x = pairing.getZr().newRandomElement();	
		
		//���ɹ�Կpk
		Element pk = g2.powZn(x); // We need to duplicate g because it's a system parameter.
		keyMap.put(SECRETKEY, x);
		keyMap.put(PUBLICKEY, pk);
		return keyMap;
		
	}
	
	/**
	 * ����У��Ԫ�������ڵ�����
	 * @param blockid
	 * @param bdata
	 * @param x ˽Կ
	 * @return
	 */
	public Map<String,Element> metaGen(byte[] blockid,byte[] bdata,Element x){
		
		//��=g1^a
		//Element a= pairing.getZr().newRandomElement();
		//Element ��= g1.powZn(a);	
		
		
		//��=g1^H(B.id)B
		Element h=pairing.getZr().newElementFromHash(blockid, 0, blockid.length);
		Element B=pairing.getZr().newElementFromBytes(bdata);
		Element ��=g2.powZn(h.mul(B));
		
		//��=f(��^1/x)		
		Element ��=pairing.getG2().newElement(��.powZn(x.invert()));//xΪ˽Կ
		
		Map<String,Element> metamap=new HashMap<String,Element>(2);
		//metamap.put("��",��);
		metamap.put("��", ��);			
		return metamap;
		
	}
	
	public void challenge(Element pk,byte[] blockid){
		//����������������У����Ϣ
		Random random = new Random();
		int int_max = java.lang.Integer.MAX_VALUE ;
		int r = 1 + random.nextInt(int_max - 1); 
		//���� <r,blockId>
	}
	public Element genProof(byte[] blockid,byte[]bdata){
		//��'=g2^H(B.id)B
		Element h=pairing.getZr().newElementFromHash(blockid, 0, blockid.length);
		Element B=pairing.getZr().newElementFromBytes(bdata);
		Element _��=g2.powZn(h.mulZn(B));		
		return _��;				//��������֤�ݷ��ظ�У����
	
	}
	public boolean proofVerify(Element ��,Element pk,Element _��){
		Element temp2 = pairing.pairing(_��, g2);
		
		Element temp1 = pairing.pairing(��, pk);	
		
		return temp1.equals(temp2)? true :false;
			
	}
	
	public static void println(Object o){
		System.out.println(o);
	}
	
		
	public static void main (String [] args) throws Exception{		
		byte[] b="asbdfsdfafsaffafaffafafaffff".getBytes();
		byte[] blockid="4".getBytes();			
		ECCBM2 ecbm=new ECCBM2(false,"pairing/a/a_181_603.properties");		
		Stopwatch start1=new  Stopwatch();		
		//��ʼ����
		ecbm.setup();
		
		//��Կ����
		Map<String,Element> keyMap=ecbm.keyGen();	
		
		 
		//Ԫ��������
		Map<String,Element> meta=ecbm.metaGen(blockid, b, keyMap.get(SECRETKEY));
		System.out.println(start1.elapsedTime());
		
	
		//������ս
		ecbm.challenge(keyMap.get(PUBLICKEY), blockid);
		//b="false".getBytes();
		//����֤��
		Stopwatch start2=new  Stopwatch();	
		Element proof =ecbm.genProof(blockid, b);	
		//println(meta.get("��"));
		//��֤�����
		System.out.println(start2.elapsedTime());
		Stopwatch start3=new  Stopwatch();	
		assertTrue(ecbm.proofVerify(meta.get("��"),keyMap.get(PUBLICKEY),proof));
		assertFalse(ecbm.proofVerify(meta.get("��"),keyMap.get(PUBLICKEY),proof.twice()));
		
		System.out.println(start3.elapsedTime());
	}

}
