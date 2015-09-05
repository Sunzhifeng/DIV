package baseModel;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import static org.junit.Assert.assertFalse;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import tool.Accumulator;
import tool.Stopwatch;
public class BLS_01  {	
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

	public BLS_01(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}
	/**
	 * 初始化参数设置
	 */
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g1 = pairing.getG1().newRandomElement().getImmutable();	
		g2 = pairing.getG2().newRandomElement().getImmutable();
	}
	/**
	 * 生成初始化公钥和私钥
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
	 * 对信息进行签名
	 * @param id 块的编号
	 * @param m  块的信息
	 * @param secretKey
	 * @return
	 */
	public Element sign(String id,String message, Element secretKey){
	
		byte[] idbytes = id.getBytes();	
		
		//源数据处理成大整数：message->Zr
		Element m = pairing.getZr().newElementFromBytes(message.getBytes());
		
		//数据id映射成G1中：id->G1
		Element h = pairing.getG1().newElementFromHash(idbytes, 0, idbytes.length);		
		
		//签名：(H(id)*g1^m)^(1/x)
		Element β=h.mul(g1.powZn(m));
		Element σ=β.powZn(secretKey.invert());//对消息的签名为sig
		return σ;
	}
	
	/**
	 * 对信息进行签名
	 * @param id 块的编号
	 * @param m  块的信息
	 * @param secretKey
	 * @return
	 */
	public Element sign2(String id,String message, Element secretKey){
	
		byte[] idbytes = id.getBytes();	
		
		//源数据处理成大整数：message->Zr
		Element m = pairing.getZr().newElementFromBytes(message.getBytes());
		
		//数据id映射成Zr中：id->Zr
		Element hr = pairing.getZr().newElementFromHash(idbytes, 0, idbytes.length);		
		
		//签名：(g1^(H(id)*m))^(1/x)
		Element β=hr.mulZn(m);
		Element σ=g1.powZn(β).powZn(secretKey.invert());//对消息的签名为sig
			
		return σ;
	}
	/**
	 * 验证签名的有效性
	 * @param pk		公钥
	 * @param id		数据块的id
	 * @param message	数据信息
	 * @param sig		签名
	 * @return
	 */
	public boolean proofVerify(Element pk, String id, String message,Element sig){
		
		//再次映射m的哈希值
		byte[] idbytes = id.getBytes(); 
		byte[] mbytes=message.getBytes();
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element h = pairing.getG1().newElementFromHash(idbytes, 0, idbytes.length);
		
		Element _β=h.mul(g1.powZn(m));
		
		// 验证签名有效性
		Element temp1 = pairing.pairing(_β, g2);
		Element temp2 = pairing.pairing(sig, pk);
		return temp1.equals(temp2)? true :false;
	}
	
	/**
	 * 验证签名的有效性
	 * @param pk		公钥
	 * @param id		数据块的id
	 * @param message	数据信息
	 * @param sig		签名
	 * @return
	 */
	public boolean proofVerify2(Element pk, String id, String message,Element sig){
		
		//再次映射m的哈希值
		byte[] idbytes = id.getBytes(); 
		byte[] mbytes=message.getBytes();
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element hr = pairing.getZr().newElementFromHash(idbytes, 0, idbytes.length);
		Element _β=g1.powZn(hr.mulZn(m));
		
		// 验证签名有效性
		Element temp1 = pairing.pairing(_β, g2);
		Element temp2 = pairing.pairing(sig, pk);
		return temp1.equals(temp2)? true :false;
	}
	public static void print(String s,Object o){
		System.out.println(s+"="+o);
	}
	public static void main (String [] args) throws Exception{
		Accumulator acc=new Accumulator();//累加器，多次取平均
		for(int i=0;i<10;i++){				
		BLS_01 bls=new BLS_01(false, "pairing/d/d_159.properties");		
		Stopwatch start=new Stopwatch();//计时器
		
		//1.初始化设置
		bls.setup();	
		
		//2.生成密钥
		Map<String,Element> keyMap=bls.keyGen();		
		String message="abcde";  //测试数据
		String id="12";			//数据id
		
		//3.私钥对数据进行签名	
		Element sig=bls.sign(id,message,keyMap.get(SECRETKEY));
		
		//4.对签名验证
		assertTrue(bls.proofVerify(keyMap.get(PUBLICKEY),id,message,sig));		
		assertFalse(bls.proofVerify(keyMap.get(PUBLICKEY),id,message+"false",sig));
		acc.addDataValue(start.elapsedTime());//增加累加器的值
		}
		System.out.println(acc.mean());//输出平均完成时间
	}

}
