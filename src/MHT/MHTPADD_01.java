/**
 * ����������
 * 1.���ڿ��У��
 * 2.������У��
 * 	
 */

package MHT;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sigAlg.DSACoder;
import tool.StdOut;
/**
 * ����MHTPADD������������У��ƻ�
 * @author MichaelSun
 * @version 1.1
 * @date 2014.12.24
 */
public class MHTPADD_01 {	
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g;	

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
	public MHTPADD_01(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}

	/**
	 * ��ʼ������
	 */
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g = pairing.getG1().newRandomElement().getImmutable();
	}
	
	/**
	 * ���ڲ�����ǩ�����ֵu
	 * @return
	 */
	public Element genRandomU(){
		return pairing.getG1().newRandomElement();
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
		Element v = g.duplicate().powZn(x); 
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

	/**
	 * ��ĳ��ӳ�䵽Zp�еĴ�������mi->Zp
	 * @param blockData    ���ݿ��Դ����
	 * @return  		   Zp�еĴ�����
	 */
	public Element preProcessFileBolck(byte[] blockData){
		Element m=pairing.getZr().newElementFromBytes(blockData);		
		return m;
	}

	/**
	 * 	���������ݿ�ת����Zp�еĴ�����
	 * @param data  Ԥ���������
	 * @return	   	 ��������		
	 */
	public Element[] allFieldElement(BigInteger[] data){//ÿ�����Ӧһ��������
		int n=data.length;
		Element[] pfield=new Element[n];
		for(int i=0;i<n;i++){
			pfield[i]=preProcessFileBolck(data[i].toByteArray());

		}
		return pfield;
	}

	/**
	 * ��Zp�����ݿ�ӳ�䵽ȺG�У�H(m1)...H(mn)->G
	 * @param pfield
	 * @return
	 */
	public Element[] allGElement(Element[]pfield){
		int length=pfield.length;
		Element[] gdata=new Element[length];		
		for(int i=0;i<length;i++){
			gdata[i]=pairing.getG1().newElementFromHash(pfield[i].toBytes(),0,pfield[i].getLengthInBytes());
			//StdOut.println((i+1)+"block "+new String(Hex.encode(gdata[i].toBytes())));
			//StdOut.print((i+1)+"block ");
		}
		StdOut.println();
		return gdata;
	}
	
	/**
	 * ����ļ�Ԫ��Ϣ��ǩ
	 * @param fileName    �ļ���
	 * @param blockNums   �ļ�����
	 * @param u			     ���ڼ����ǩ�����ֵ	
	 * @return            �ļ�Ԫ��Ϣ����������֤
	 * 
	 */
	public byte[] fileTagGen(String fileName,int blockNums,Element u) throws Exception{
		Map<String,Object>sigKey=DSACoder.initKey();
		String data=fileName+String.valueOf(blockNums)+u.toString();
		//DSA�������ļ���Ԫ��Ϣǩ��
		String sigFileMeta=DSACoder.sign(data.getBytes(),DSACoder.getPrivateKey(sigKey)).toString();
		return (data+sigFileMeta).getBytes();
	}

	/**
	 * Ϊÿ�����ݿ��������ݱ�ǩt
	 * @param blockNum		�ļ�����
	 * @param mi	 		������
	 * @param Hmi			miӳ�䵽G��
	 * @param x				��Կ
	 * @param u				���������
	 * @return				���ݱ�ǩֵ
	 */
	public Element metaGen(int blockNum,Element mi,Element Hmi,Element x,Element u){
		//�����ļ����ǩ��t=(H(m)*u^m)^x		
		Element t=(Hmi.duplicate().mul(u.duplicate().powZn(mi))).powZn(x);       
		return t;
	}

	/**
	 * ��MHT��Root����ǩ��
	 * @param R
	 * @param x
	 * @return
	 */
	public Element sigRoot(byte[]R ,Element x){	
		//sig(H(R))<-(H(R))^x
		Element sigR=pairing.getG1().newElementFromHash(R,0,R.length).powZn(x);
		return sigR;		
	}

	/**
	 * ���MHT��Root��ֵ
	 * @param blocks  H(mi)������
	 * @param n	      ����
	 * @return     MHT����ֵ
	 * @throws Exception
	 */
	public byte[] getMHTRoot(Element[] blocks,int n) throws Exception{
		return new MerkleHashTree(blocks).createMHT();
	}

	/**
	 * У����������ս��Ϣ����ŵ�ȫ�ֱ���challenge��
	 * @param c   			У�����
	 * @param allBlocks   	ȫ������
	 * return 				��ս����
	 */
	public Chal[] challengeGen(int c,int allBlocks){
		int []ran=new int[c];
		ran=random(1,allBlocks,c); //1-allBlocks�е�c����ͬ����
		Chal[] challenge=new Chal[c];		
		//����ÿ���Ӧ�������vi
		for(int i=0;i<c;i++){
			//StdOut.println(ran[i]);
			challenge[i]=new Chal(ran[i],pairing.getZr().newRandomElement());
			//StdOut.println("ChanllengeNum: "+challenge[i].num);
		}
		return challenge;
	}
	//�Ľ���ս�Ĵ�������������+һ�������������k1
	public Chal[] challengeGen2(int c,int allBlocks){
		int []ran=new int[c];		
		Chal[] challenge=new Chal[c];	
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();
		BigInteger k2=pairing.getZr().newRandomElement().toBigInteger();
		ran=random(1,allBlocks,c,k2.longValue()); //1-allBlocks�е�c����ͬ����
		//k1�������ӣ�����ÿ���Ӧ�������vi
		for(int i=0;i<c;i++){			
			challenge[i]=new Chal(ran[i],pairing.getZr().newElement(k1.add(BigInteger.valueOf(ran[i]))));
			//StdOut.println("ChanllengeNum: "+challenge[i].num);
		}
		return challenge;
	}
	/**
	 * ����ָ����Χ�ڵĶ�����ظ��������
	 * @param start	��Сֵ
	 * @param end	���ֵ
	 * @param len	����
	 * @return
	 */
	public  int[] random(int start,int end,int len){
		int [] rst=new int[len];
		Arrays.fill(rst,start-1);
		Random r=new Random();
		for (int i = 0; i < rst.length; ) {
			int ran=r.nextInt(end-start+1)+start;
			if(!isDup(rst, ran)){
				rst[i++]=ran;
			}

		}
		return rst;
	}

	public  int[] random(int start,int end,int len,long seek){
		int [] rst=new int[len];
		Arrays.fill(rst,start-1);
		Random r=new Random(seek);
		for (int i = 0; i < rst.length; ) {
			int ran=r.nextInt(end-start+1)+start;
			if(!isDup(rst, ran)){
				rst[i++]=ran;
				System.out.println("num:"+ran);
			}
		
		}
		return rst;
	}
	/**
	 * �Ƿ�����ظ��������
	 * @param random   �����ɵ������
	 * @param ran	       �����ɵ������
	 * @return
	 */
	boolean  isDup(int []random,int ran){
		for (int i = 0; i < random.length; i++) {
			if(random[i]==ran)
				return true;//ran�Ƿ���random������
		}
		return false;
	}


	/**
	 * CSP��������������֤��proof���������ۼӺͱ�ǩ�۳���Ϣ
	 * @param vi ÿ����ս���Ӧ�������
	 * @param mi ÿ����Ԫ��pfield
	 * @param ti ÿ�����Ԫ��ǩ	
	 * @return	֤�ݵļ���
	 */
	public Map<String,Object> genProof(Element[] vi,Element[] mi,Element[] ti){		
		int c=vi.length;
		Element aggreSum=pairing.getZr().newZeroElement();
		Element aggreMul=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			//sum(vi*mi)
			aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mi[i]));
			//mul(ti^vi)
			aggreMul=aggreMul.mul(ti[i].duplicate().powZn(vi[i]));
		}
		
		Map<String,Object>proof=new HashMap<String,Object>(5);	    
		proof.put("aggreSum", aggreSum);
		proof.put("aggreMul", aggreMul);		
		return proof;
	}

	/**
	 * CSP������У��֤��proof���������ۼӺͱ�ǩ�۳���Ϣ
	 * @param vki ÿ����ս���Ӧ�������(���Կ��ǣ���������ɷ����������ɣ��������ݴ�������
	 * @param mki k���û�Ҫ�������ݿ�
	 * @param tki k���û����ݶ�Ӧ��Ԫ��ǩ	 
	 * @return
	 */
	public Map<String,Object> genBathProof(List<Chal[]> challenges,List<Element[]> kmi,List<Element[]> kti){
		int K=challenges.size();
		Element [] kaggreSum=new Element[K];		
		Element kaggreMul=pairing.getG1().newOneElement();
		for(int k=0;k<K;k++){
			Element aggreSum=pairing.getZr().newZeroElement();
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//��k����ս�Ŀ�����
			Element[] mi=(Element[])kmi.get(k);
			Element[] ti=kti.get(k);
			for(int i=0;i<CBCounts;i++){				
				//sum(vi*mki),k=1...K
				aggreSum=aggreSum.add((chal[i].random.duplicate()).mulZn(mi[i]));
				//mul(tki^vi),k=1...K
				kaggreMul=kaggreMul.mul(ti[i].duplicate().powZn(chal[i].random));

			}
			kaggreSum[k]=aggreSum;
		}		
		Map<String,Object>proof=new HashMap<String,Object>(5);	    
		proof.put("kaggreSum", kaggreSum);
		proof.put("kaggreMul", kaggreMul);				
		return proof;
	}
	/**
	 * У������֤proof�Ƿ���ȷ
	 * @param R MHT��Rootֵ����Ӧ������ս��Ĺ�ϣ���丨�����������R
	 * @param v �û���Կ
	 * @param sigHashRoot ǩ������MHT��H(R)
	 * @return true��false
	 */
	public boolean proofVerify(byte[]R,Element v,Element u,Chal[] chal,Map<String,Object> proof){

		//R<-genRoot(Element[] HashM,Qi)
		Element hashR=pairing.getG1().newElementFromHash(R, 0, R.length);
		Element sigHashRoot=(Element)proof.get("sigHashRoot");
		Element temp1 = pairing.pairing(sigHashRoot, g);
		Element temp2 = pairing.pairing(hashR, v);			
		Element aggreMul=(Element)proof.get("aggreMul");
		Element aggreSum=(Element)proof.get("aggreSum");
		Element[] Hmi=(Element[])proof.get("Hmi");

		//h(mi)^vi
		int c=Hmi.length;
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){			
			Element tmp=Hmi[i].duplicate().powZn(chal[i].random);
			aggreBlock=aggreBlock.duplicate().mul(tmp);
		}

		//u^u
		Element u_=u.duplicate().powZn(aggreSum);
		Element l=aggreBlock.duplicate().mul(u_);	    
		Element temp3 =pairing.pairing(aggreMul, g);		
		Element temp4 = pairing.pairing(l, v);	

		return (temp1.equals(temp2)&&temp3.equals(temp4))? true :false;

	}
	//������֤֤��,���Կ����۳�K��sigHashRoot�Լ��ٴ�����

	/**
	 * ������֤K���û���������֤��
	 * @param challenges k����ս�ļ���
	 * @param kRoot	  k��MHT����ֵ
	 * @param kv	  k����Կ
	 * @param ku	  k���û����ɱ�ǩ������ֵ 
	 * @param proof		֤��
	 * @return
	 */
	public boolean proofBathVerify(List<Chal[]>challenges,BigInteger []kRoot,Element[] kv,Element[] ku,Map<String,Object>proof){
		Element[] ksigHashRoot=(Element[])proof.get("ksigHashRoot");
		List<Element[]>kHmi=(List<Element[]>)proof.get("kHmi");
		Element kaggreMul=(Element)proof.get("kaggreMul");
		Element[] kaggreSum=(Element[])proof.get("kaggreSum");

		//��֤K��MHT��R
		//boolean MHTR=true;
		int K=kv.length;
		Element []kHashR=new Element[K];//������ʱ�����H(R)
		for(int k=0;k<K;k++){
			byte[] data=kRoot[k].toByteArray();
			Element hashR=pairing.getG1().newElementFromHash(data, 0, data.length);
			kHashR[k]=hashR.duplicate();
			Element temp1 = pairing.pairing(ksigHashRoot[k], g);
			Element temp2 = pairing.pairing(hashR, kv[k]);	
			if(!temp1.equals(temp2)){
				StdOut.println("MHT_Root��֤����");
				//MHTR=false;
				return false;
			}
		}


		Element agg=pairing.getGT().newOneElement();
		for(int k=0;k<K;k++){
			Element aggreBlock=pairing.getG1().newOneElement();
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//��k����ս�Ŀ�����
			Element[] Hmi=kHmi.get(k);
			//H(mki)^vi
			for(int i=0;i<CBCounts;i++){			
				Element tmp=Hmi[i].duplicate().powZn(chal[i].random);
				aggreBlock=aggreBlock.duplicate().mul(tmp);
			}

			//u^u
			Element u_=ku[k].duplicate().powZn(kaggreSum[k]);
			Element l=aggreBlock.duplicate().mul(u_);		
			agg=agg.mul(pairing.pairing(l, kv[k]));	
		}
		Element temp3 =pairing.pairing(kaggreMul, g);		
		return temp3.equals(agg)? true :false;

	}
	//�Ը�ǩ�������۳�
	public boolean proofBathVerify2(List<Chal[]>challenges,BigInteger []kRoot,Element[] kv,Element[] ku,Map<String,Object>proof){
		Element ksigHashRootAggre=(Element)proof.get("ksigHashRootAggre");
		List<Element[]>kHmi=(List<Element[]>)proof.get("kHmi");
		Element kaggreMul=(Element)proof.get("kaggreMul");
		Element[] kaggreSum=(Element[])proof.get("kaggreSum");

		//��֤K��MHT��R
		int K=kv.length;
		//Element []kHashR=new Element[K];//������ʱ�����H(R)
		Element temp2=pairing.getGT().newOneElement();
		for(int k=0;k<K;k++){
			byte[] data=kRoot[k].toByteArray();
			Element hashR=pairing.getG1().newElementFromHash(data, 0, data.length);
			temp2=temp2.mul(pairing.pairing(hashR, kv[k]));	
		}
		Element temp1=pairing.pairing(ksigHashRootAggre, g);
		
		//��֤����
		Element temp4=pairing.getGT().newOneElement();
		for(int k=0;k<K;k++){
			Element aggreBlock=pairing.getG1().newOneElement();
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//��k����ս�Ŀ�����
			Element[] Hmi=kHmi.get(k);
			//H(mki)^vi
			for(int i=0;i<CBCounts;i++){			
				Element tmp=Hmi[i].duplicate().powZn(chal[i].random);
				aggreBlock=aggreBlock.duplicate().mul(tmp);
			}

			//u^u
			Element u_=ku[k].duplicate().powZn(kaggreSum[k]);
			Element l=aggreBlock.duplicate().mul(u_);		
			temp4=temp4.mul(pairing.pairing(l, kv[k]));	
		}
		Element temp3 =pairing.pairing(kaggreMul, g);		
		return temp1.equals(temp2)&&temp3.equals(temp4)? true :false;

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
