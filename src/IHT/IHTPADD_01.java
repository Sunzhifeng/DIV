/**
 * ����������
 * 1.�ǶԳ�˫����ӳ��
 * 2.����������ϣ������ǩ������
 */

package IHT;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import IHT.IndexHashTable.Item;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sigAlg.DSACoder;
import tool.GenerateRandom;
import tool.StdOut;
/**
 * ����IndexHashTableʵ�ֵ�����У�鷽��
 * @author MichaelSun
 * @version 1.0
 * @date 2014.12.23
 */
public class IHTPADD_01 {
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g1;	
	private Element g2;	
	public  String fileId;

	/**
	 * ��ս��Ϣ���ڲ���
	 */
	public  static class Chal{
		int num; //����߼����
		Element random;//��Ӧ�������
		public Chal(int num,Element random){
			this.num=num;
			this.random=random;
		}

	}
	/**
	 * ��ʼ��У�����
	 * @param usePBC
	 * @param curvePath
	 */
	public IHTPADD_01(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}

	/**
	 * ��ʼ������
	 * @param s ���ݿ�Ķ���
	 */
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g1 = pairing.getG1().newRandomElement().getImmutable();		
		g2= pairing.getG2().newRandomElement().getImmutable();		
	}
	/**
	 * ���ɳ�ʼ����Կ
	 * @return
	 */
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);

		//������Կx
		Element x = pairing.getZr().newRandomElement().getImmutable();	

		//���ɹ�Կpk
		Element v = g2.duplicate().powZn(x); 
		keyMap.put(SECRETKEY, x);
		keyMap.put(PUBLICKEY, v);
		return keyMap;

	}
	/**
	 * ����ǩ����Կ��DSA
	 * ����ǩ���㷨��SHA1withDSA
	 * @return
	 */
	public static Map<String, Object> sigKeyGen()throws Exception{
		return DSACoder.initKey();	

	}

	/*//H(m1)...H(mn)����>��G��
	public Element[] allGElement(Element[]pfield){
		int length=pfield.length;
		Element[] gdata=new Element[length];
		StdOut.println("H(mi)->g��");
		for(int i=0;i<length;i++){
			gdata[i]=pairing.getG1().newElementFromHash(pfield[i].toBytes(),0,pfield[i].getLengthInBytes());
			//StdOut.println((i+1)+"block "+new String(Hex.encode(gdata[i].toBytes())));
			StdOut.print((i+1)+"block ");
		}
		StdOut.println();
		return gdata;
	}*/



	/**
	 * ����ļ�Ԫ��Ϣ��ǩ�������ڷֶεĴ���
	 * @param fileName    �ļ���
	 * @param blockNums   �ļ�����	
	 * @return            �ļ�Ԫ��Ϣ����������֤
	 * @throws Exception
	 */
	public byte[] fileTagGen(String fileName,int blockNums,Element[]us) throws Exception{
		Map<String,Object>sigKey=DSACoder.initKey();
		String data=fileName+String.valueOf(blockNums)+elementSCat(us).toString();

		String sigFileMeta=DSACoder.sign(data.getBytes(),DSACoder.getPrivateKey(sigKey)).toString();

		return (data+sigFileMeta).getBytes();
	}

	/**
	 * Ϊ�ļ�����������ϣ��
	 * @param fileID	�ļ���ʾ
	 * @param blockNums	�ļ��������Ŀ���
	 * @param x			�û���˽Կ������IHT�ı������ǩ������������Ҳ�ɿ��ǲ��ñ�׼����ǩ��DSA
	 * @return
	 */
	public Item[] genIHT(String fileID,int blockNums,Element x){
		IndexHashTable ihtable=new IndexHashTable(fileID,blockNums);
		//ihtable.createIHT(pairing.getZr(),x , pairing.getG1());		
		return ihtable.createIHT(pairing.getZr(),x , pairing.getG1());		

	}

	/**
	 * �������s��G��Ԫ��
	 * @param ps	s�����Zp��Ԫ��
	 */
	public Element[] usGen(Element[]ps){
		int s=ps.length ;
		Element []us=new Element[s];	
		for(int i=0;i<s;i++){			
			//ui=g^ai
			us[i]=g1.powZn(ps[i]);	
		}
		return us;
	}

	public Element[] psGen(int s){
		Element[]ps=new Element[s];
		for(int i=0;i<s;i++){
			//a1,...as
			ps[i]=pairing.getZr().newRandomElement();
		}
		return ps;
	}
	/**
	 * ��IDiӳ�䵽G��
	 * @param item IHT�е�һ������
	 * @return 
	 */
/*	public Element genHid(Item item){
		return pairing.getG1().newElementFromBytes(item.getContact().getBytes());

	}*/

	/**
	 * ���ɵĿ��ǩ
	 * @param blockNum 	�ļ�����
	 * @param Hid		��������Ϣӳ�䵽G��Ԫ��
	 * @param x			��Կ
	 * @param mij		���еĶ�Ԫ������
	 * @return			�ļ����ǩ
	 */
	public Element metaGen(int blockNum,Element Hid,Element x,Element[]mij,Element[]ps){
		int s=mij.length;		
		//�����ļ����ǩ��t=(H(filename||Bi||vi||R)*(��uj^mij))^x
		Element aggSum =pairing.getZr().newZeroElement();
		for(int i=0;i<s;i++){
			aggSum=aggSum.add(ps[i].duplicate().mulZn(mij[i]));
		}		
		Element t=(Hid.duplicate().mul(g1.duplicate().powZn(aggSum))).powZn(x);       
		return t;
	}





	/**
	 * У����������ս��Ϣ����ŵ�ȫ�ֱ���challenge��
	 * @param c   			У�����
	 * @param allBlocks   	ȫ������
	 * 
	 */
	public Chal[] challengeGen(int c,int allBlocks,String fileId){
		int []ran=new int[c];
		ran=GenerateRandom.random(1,allBlocks,c); //1-allBlocks�е�c����ͬ����
		Chal[]challenge=new Chal[c];		
		//����ÿ���Ӧ�������vi
		for(int i=0;i<c;i++){			
			challenge[i]=new Chal(ran[i],pairing.getZr().newRandomElement());
		}
		this.fileId=fileId;		
		return challenge;
	}




	/**
	 * CSP��������������֤��proof
	 * @param vi ÿ����ս���Ӧ�������	
	 * @param ti ÿ�����Ԫ��ǩ
	 * @param sigHashRoot ǩ������MHT��H(R)
	 * @return
	 */
	public Map<String,Object> genProof(Element[] vi,Element[][] mij,Element[] ti,Element[] us){
		//�������ʱ����һ�����⣺ÿ�����ģ�����㣬���Ƕ���ͽ������ģ�����㣬��ʱ��ȡǰ��
		int s=us.length;
		int c=vi.length;			
		Element []sAggreSum=new Element[s];//���s�����ݶε��ۼӵ�ֵ
		Element aggreMul=pairing.getG1().newOneElement();
		Element aggreSum;
		//���ݿ���ۼ�
		for(int k=0;k<s;k++){
			aggreSum=pairing.getZr().newZeroElement();//ÿ����������һ����ʼ0Ԫ��
			for(int i=0;i<c;i++){
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][k]));
			}
			sAggreSum[k]=aggreSum;

		}
		//���ݱ�ǩ���۳�
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreMul=aggreMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//����mi���ɶ�Ӧ��{h(mi),Qi},���͸�verifier��������R�Ա���֤
		//ȫ�ֱ���proof������Ϣ
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("sAggreSum", sAggreSum);
		proof.put("aggreMul", aggreMul);		
		return proof;


	}


	/**
	 * ����CSP������Proof,У������֤Proof�Ƿ���ȷ	
	 * @param v ��Կ	
	 * @return  true��false
	 */
	public boolean proofVerify(Chal[]challenge,Element v, Map<String,Object> proof,Element[]us){

		int s=us.length;		
		Element aggreMul=(Element)proof.get("aggreMul");
		Element[] sAggreSum=(Element[])(proof.get("sAggreSum"));
		Item[] id=(Item[])proof.get("id");

		//h(Idi)^vi
		int c=id.length;
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
			Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
			Element tmp=Hid.duplicate().powZn(challenge[i].random);
			aggreBlock=aggreBlock.duplicate().mul(tmp);
		}


		//��u^��
		Element u_=pairing.getG1().newOneElement();
		for(int j=0;j<s;j++){					
			u_=u_.mul(us[j].powZn(sAggreSum[j]));
		}
		Element l=aggreBlock.mul(u_);	    
		Element temp3 =pairing.pairing(aggreMul, g2);		
		Element temp4 = pairing.pairing(l, v);			
		return temp3.equals(temp4)? true :false;

	}
	/**
	 * ���Ԫ�ص����Ӳ��� 
	 * @param us
	 * @return
	 */
	public byte[] elementSCat(Element[]us){//������ַ����������������𣿣�
		int s=us.length;
		byte[] result=us[0].toBytes();

		for(int i=1;i<s;i++){
			result=arraycat(result,us[i].toBytes());
		}
		return result;
	}
	/**
	 * �������ַ�����
	 * @param buf1	����1
	 * @param buf2	����2
	 * @return		�����������ӽ��
	 */
	public byte[] arraycat(byte[] buf1,byte[] buf2)
	{
		byte[] bufret=null;
		int len1=0;
		int len2=0;
		if(buf1!=null)
			len1=buf1.length;
		if(buf2!=null)
			len2=buf2.length;
		if(len1+len2>0)
			bufret=new byte[len1+len2];
		if(len1>0)
			System.arraycopy(buf1,0,bufret,0,len1);
		if(len2>0)
			System.arraycopy(buf2,0,bufret,len1,len2);
		return bufret;
	}


	

	public Pairing getPairing() {
		return pairing;
	}	

	


}
