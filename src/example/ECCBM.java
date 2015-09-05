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
public class ECCBM {	
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g1;
	private Element g2;	
	private Element gT;

			
	public static Collection parameters() {
		Object[][] data = {
				{false, "pairing/a/a_181_603.properties"},
				{true, "pairing/d/d_9563.properties"},
		};
		PairingFactory.getInstance().setReuseInstance(false);
		return Arrays.asList(data);
	}

	public ECCBM(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g1 = pairing.getG1().newRandomElement().getImmutable();
		g2 = pairing.getG2().newRandomElement().getImmutable();	
		
	}
	/**
	 * 
	 * @return
	 */
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);
		
		//
		Element x = pairing.getZr().newRandomElement();	
		
		//
		Element pk = g2.powZn(x); // We need to duplicate g because it's a system parameter.
		keyMap.put(SECRETKEY, x);
		keyMap.put(PUBLICKEY, pk);
		return keyMap;
		
	}
	
	public Map<String,Element> metaGen(byte[] blockid,byte[] bdata,Element x){
		
		
		
		//t=g1^H(B.id)B
		Element h=pairing.getZr().newElementFromHash(blockid, 0, blockid.length);
		Element B=pairing.getZr().newElementFromBytes(bdata);
		Element t=g1.powZn((h.mul(B)));
		
		//ti=f(t^1/x)		
		Element ti=(t.powZn(x.invert()));//
		
		Map<String,Element> metamap=new HashMap<String,Element>(2);
		//metamap.put("��",��);
		metamap.put("ti", ti);			
		return metamap;
		
	}
	
	public void challenge(Element pk,byte[] blockid){
		Element ran=pairing.getZr().newRandomElement();
		byte[] data="test".getBytes();
		Element temp1=ran.getField().newElementFromHash(data, 0, data.length);
		Element temp2=pairing.getZr().newElementFromHash(data, 0, data.length);
		System.out.println((temp1.equals(temp2)? "true":"false"));
	}
	public Element genProof(byte[] blockid,byte[]bdata){
		//_t=g2^H(B.id)B
		Element h=pairing.getZr().newElementFromHash(blockid, 0, blockid.length);
		Element B=pairing.getZr().newElementFromBytes(bdata);
		Element _t=g1.powZn(h.mulZn(B));		
		return _t;				
	
	}
	public boolean proofVerify(Element ti,Element pk,Element _t){
	
	
		Element temp1 = pairing.pairing(ti, pk);	
		Element temp2 = pairing.pairing(_t, g2);
		
		
		
		return temp1.equals(temp2)? true :false;
			
	}
	
	public static void println(Object o){
		System.out.println(o);
	}
	
		
	public static void main (String [] args) throws Exception{		
		byte[] b="asbdf".getBytes();
		byte[] blockid="4".getBytes();			
		ECCBM ecbm=new ECCBM(false,"pairing/d/d_9563.properties");		
		Stopwatch start=new  Stopwatch();		
		
		ecbm.setup();
		
		
		Map<String,Element> keyMap=ecbm.keyGen();	
		
		 
		
		Map<String,Element> meta=ecbm.metaGen(blockid, b, keyMap.get(SECRETKEY));
		
	
		ecbm.challenge(keyMap.get(PUBLICKEY), blockid);
		
		
		Element proof =ecbm.genProof(blockid, b);	
		
		
		assertTrue(ecbm.proofVerify(meta.get("ti"),keyMap.get(PUBLICKEY),proof));
		assertFalse(ecbm.proofVerify(meta.get("ti"),keyMap.get(PUBLICKEY),proof.twice()));
		
		System.out.println(start.elapsedTime());
	}

}
