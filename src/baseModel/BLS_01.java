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
	 * ��ʼ����������
	 */
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g1 = pairing.getG1().newRandomElement().getImmutable();	
		g2 = pairing.getG2().newRandomElement().getImmutable();
	}
	/**
	 * ���ɳ�ʼ����Կ��˽Կ
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
	 * ����Ϣ����ǩ��
	 * @param id ��ı��
	 * @param m  �����Ϣ
	 * @param secretKey
	 * @return
	 */
	public Element sign(String id,String message, Element secretKey){
	
		byte[] idbytes = id.getBytes();	
		
		//Դ���ݴ���ɴ�������message->Zr
		Element m = pairing.getZr().newElementFromBytes(message.getBytes());
		
		//����idӳ���G1�У�id->G1
		Element h = pairing.getG1().newElementFromHash(idbytes, 0, idbytes.length);		
		
		//ǩ����(H(id)*g1^m)^(1/x)
		Element ��=h.mul(g1.powZn(m));
		Element ��=��.powZn(secretKey.invert());//����Ϣ��ǩ��Ϊsig
		return ��;
	}
	
	/**
	 * ����Ϣ����ǩ��
	 * @param id ��ı��
	 * @param m  �����Ϣ
	 * @param secretKey
	 * @return
	 */
	public Element sign2(String id,String message, Element secretKey){
	
		byte[] idbytes = id.getBytes();	
		
		//Դ���ݴ���ɴ�������message->Zr
		Element m = pairing.getZr().newElementFromBytes(message.getBytes());
		
		//����idӳ���Zr�У�id->Zr
		Element hr = pairing.getZr().newElementFromHash(idbytes, 0, idbytes.length);		
		
		//ǩ����(g1^(H(id)*m))^(1/x)
		Element ��=hr.mulZn(m);
		Element ��=g1.powZn(��).powZn(secretKey.invert());//����Ϣ��ǩ��Ϊsig
			
		return ��;
	}
	/**
	 * ��֤ǩ������Ч��
	 * @param pk		��Կ
	 * @param id		���ݿ��id
	 * @param message	������Ϣ
	 * @param sig		ǩ��
	 * @return
	 */
	public boolean proofVerify(Element pk, String id, String message,Element sig){
		
		//�ٴ�ӳ��m�Ĺ�ϣֵ
		byte[] idbytes = id.getBytes(); 
		byte[] mbytes=message.getBytes();
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element h = pairing.getG1().newElementFromHash(idbytes, 0, idbytes.length);
		
		Element _��=h.mul(g1.powZn(m));
		
		// ��֤ǩ����Ч��
		Element temp1 = pairing.pairing(_��, g2);
		Element temp2 = pairing.pairing(sig, pk);
		return temp1.equals(temp2)? true :false;
	}
	
	/**
	 * ��֤ǩ������Ч��
	 * @param pk		��Կ
	 * @param id		���ݿ��id
	 * @param message	������Ϣ
	 * @param sig		ǩ��
	 * @return
	 */
	public boolean proofVerify2(Element pk, String id, String message,Element sig){
		
		//�ٴ�ӳ��m�Ĺ�ϣֵ
		byte[] idbytes = id.getBytes(); 
		byte[] mbytes=message.getBytes();
		Element m = pairing.getZr().newElementFromBytes(mbytes);
		Element hr = pairing.getZr().newElementFromHash(idbytes, 0, idbytes.length);
		Element _��=g1.powZn(hr.mulZn(m));
		
		// ��֤ǩ����Ч��
		Element temp1 = pairing.pairing(_��, g2);
		Element temp2 = pairing.pairing(sig, pk);
		return temp1.equals(temp2)? true :false;
	}
	public static void print(String s,Object o){
		System.out.println(s+"="+o);
	}
	public static void main (String [] args) throws Exception{
		Accumulator acc=new Accumulator();//�ۼ��������ȡƽ��
		for(int i=0;i<10;i++){				
		BLS_01 bls=new BLS_01(false, "pairing/d/d_159.properties");		
		Stopwatch start=new Stopwatch();//��ʱ��
		
		//1.��ʼ������
		bls.setup();	
		
		//2.������Կ
		Map<String,Element> keyMap=bls.keyGen();		
		String message="abcde";  //��������
		String id="12";			//����id
		
		//3.˽Կ�����ݽ���ǩ��	
		Element sig=bls.sign(id,message,keyMap.get(SECRETKEY));
		
		//4.��ǩ����֤
		assertTrue(bls.proofVerify(keyMap.get(PUBLICKEY),id,message,sig));		
		assertFalse(bls.proofVerify(keyMap.get(PUBLICKEY),id,message+"false",sig));
		acc.addDataValue(start.elapsedTime());//�����ۼ�����ֵ
		}
		System.out.println(acc.mean());//���ƽ�����ʱ��
	}

}
