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
		
		//生成密钥x
		Element x = pairing.getZr().newRandomElement();	
		
		//生成公钥pk
		Element pk = g2.powZn(x); // We need to duplicate g because it's a system parameter.
		keyMap.put(SECRETKEY, x);
		keyMap.put(PUBLICKEY, pk);
		return keyMap;
		
	}
	
	/**
	 * 生成校验元，保存在第三方
	 * @param blockid
	 * @param bdata
	 * @param x 私钥
	 * @return
	 */
	public Map<String,Element> metaGen(byte[] blockid,byte[] bdata,Element x){
		
		//α=g1^a
		//Element a= pairing.getZr().newRandomElement();
		//Element α= g1.powZn(a);	
		
		
		//β=g1^H(B.id)B
		Element h=pairing.getZr().newElementFromHash(blockid, 0, blockid.length);
		Element B=pairing.getZr().newElementFromBytes(bdata);
		Element β=g2.powZn(h.mul(B));
		
		//σ=f(β^1/x)		
		Element σ=pairing.getG2().newElement(β.powZn(x.invert()));//x为私钥
		
		Map<String,Element> metamap=new HashMap<String,Element>(2);
		//metamap.put("α",α);
		metamap.put("σ", σ);			
		return metamap;
		
	}
	
	public void challenge(Element pk,byte[] blockid){
		//给服务器发送请求校验信息
		Random random = new Random();
		int int_max = java.lang.Integer.MAX_VALUE ;
		int r = 1 + random.nextInt(int_max - 1); 
		//发送 <r,blockId>
	}
	public Element genProof(byte[] blockid,byte[]bdata){
		//β'=g2^H(B.id)B
		Element h=pairing.getZr().newElementFromHash(blockid, 0, blockid.length);
		Element B=pairing.getZr().newElementFromBytes(bdata);
		Element _β=g2.powZn(h.mulZn(B));		
		return _β;				//将产生的证据返回给校验者
	
	}
	public boolean proofVerify(Element σ,Element pk,Element _β){
		Element temp2 = pairing.pairing(_β, g2);
		
		Element temp1 = pairing.pairing(σ, pk);	
		
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
		//初始设置
		ecbm.setup();
		
		//密钥生成
		Map<String,Element> keyMap=ecbm.keyGen();	
		
		 
		//元数据生成
		Map<String,Element> meta=ecbm.metaGen(blockid, b, keyMap.get(SECRETKEY));
		System.out.println(start1.elapsedTime());
		
	
		//发起挑战
		ecbm.challenge(keyMap.get(PUBLICKEY), blockid);
		//b="false".getBytes();
		//生成证据
		Stopwatch start2=new  Stopwatch();	
		Element proof =ecbm.genProof(blockid, b);	
		//println(meta.get("σ"));
		//验证结果α
		System.out.println(start2.elapsedTime());
		Stopwatch start3=new  Stopwatch();	
		assertTrue(ecbm.proofVerify(meta.get("σ"),keyMap.get(PUBLICKEY),proof));
		assertFalse(ecbm.proofVerify(meta.get("σ"),keyMap.get(PUBLICKEY),proof.twice()));
		
		System.out.println(start3.elapsedTime());
	}

}
