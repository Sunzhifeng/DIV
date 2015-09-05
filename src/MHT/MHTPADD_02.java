/**
 * ����������
 * 1.���ӷֶεĴ����� 
 * 2.������У�鹦��
 */

package MHT;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import MHT.MHTPADD_01.Chal;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sigAlg.DSACoder;
import tool.StdOut;
/**
 * ����MHTPADD������������У��ƻ� 
 * @author MichaelSun
 * @version 2.1
 * @date 2014.11.21
 */
public class MHTPADD_02 {	
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
	public MHTPADD_02(boolean usePBC, String curvePath) {
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
		g = pairing.getG1().newRandomElement().getImmutable();		
		
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
	//blockData������mi��miΪZp��Ԫ��
	public Element preProcessFileBolck(byte[] BlockData){
		Element m=pairing.getZr().newElementFromBytes(BlockData);		
		return m;
	}
	//m1...mnΪ��P��Ԫ��
	public Element[] allFieldElement(String[] data){	
		int n=data.length;
		Element[] pfield=new Element[n];
		for(int i=0;i<n;i++){
			pfield[i]=preProcessFileBolck(data[i].getBytes());

		}
		return pfield;
	}

	//H(m1)...H(mn)����>��G��
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
	}

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
	 * ���Ԫ�ص����Ӳ��� 
	 * @param us Ԥ���������Ԫ��
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



	/**
	 * �������s��G��Ԫ��
	 * @param s
	 * @return 	s�����Ԫ��ֵ
	 */
	public Element[] pusGen(int s){//����У���ǩʱ���ټ��㿪��
		Element[] us=new Element[s];		
		for(int i=0;i<s;i++){			
			//u1...us
			us[i]=pairing.getG1().newRandomElement();	
		}
		return us;
	}



	/**
	 * ���ɵĿ��ǩ�����ֶ����
	 * @param blockNum 	�ļ�����
	 * @param mi		��Ԫ��
	 * @param Hmi		��ӳ�䵽G��Ԫ��
	 * @param x			��Կ
	 * @param mij		���еĶ�Ԫ������
	 * @return			�ļ����ǩ
	 */
	public Element metaGen(int blockNum,Element Hmi,Element x,Element[]mij,Element[]us){
		int s=mij.length;		
		//�����ļ����ǩ��t=(H(mi)*(��uj^mij))^x
		Element aggmul =pairing.getG1().newOneElement();
		for(int i=0;i<s;i++){
			aggmul=aggmul.mul(us[i].duplicate().powZn(mij[i]));
		}
		Element t=(Hmi.duplicate().mul(aggmul)).powZn(x);       
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
	 * @return				��ս��Ϣ
	 */
	public Chal[] challengeGen(int c,int allBlocks){
		int []ran=new int[c];
		ran=random(1,allBlocks,c); //1-allBlocks�е�c����ͬ����
		Chal[] challenge=new Chal[c];		
		//����ÿ���Ӧ�������vi
		for(int i=0;i<c;i++){			
			challenge[i]=new Chal(ran[i],pairing.getZr().newRandomElement());
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
	 * CSP��������������֤��proof
	 * @param vi ÿ����ս���Ӧ�������
	 * @param mi ÿ����Ԫ��pfield
	 * @param ti ÿ�����Ԫ��ǩ
	 * @param sigHashRoot ǩ������MHT��H(R)
	 * @return
	 */
	public Map<String ,Object> genProof(Element[] vi,Element[][] mij,Element[] ti,int s){
		//�������ʱ����һ�����⣺ÿ�����ģ�����㣬���Ƕ���ͽ������ģ�����㣬��ʱ��ȡǰ��
		int c=vi.length;			
		Element []sAggreSum=new Element[s];//���s�����ݶε��ۼӵ�ֵ
		Element aggreMul=pairing.getG1().newOneElement();
		Element aggreSum;
		//���ݿ���ۼӡ����޿�У��
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

		Map<String ,Object>proof=new HashMap<String,Object>(5);
		proof.put("sAggreSum", sAggreSum);
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
	public Map<String,Object> genBathProof(List<Chal[]> challenges,List<List<Element[]>> kmij,List<Element[]> kti,int s){
		int K=challenges.size(); //��ս�ĸ���
		List<Element []> ksaggreSum=new ArrayList<Element[]>(K);		
		Element kaggreMul=pairing.getG1().newOneElement();
		for(int k=0;k<K;k++){
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//��k����ս�Ŀ�����
			List<Element[]> mij=(List<Element[]>)kmij.get(k);
			Element[] ti=kti.get(k);
			Element[] saggreSum=new Element[s];

			//���������ۼ�
			for(int j=0;j<s;j++){
				Element aggreSum=pairing.getZr().newZeroElement();
				for(int i=0;i<CBCounts;i++){				
					//sum(vi*mij),j=1...s
					aggreSum=aggreSum.add((chal[i].random.duplicate()).mulZn(mij.get(i)[j]));
				}
				saggreSum[j]=aggreSum;
			}
			ksaggreSum.add(saggreSum);

			//�����ǩ�۳�
			for(int i=0;i<CBCounts;i++){			
				//mul(tki^vi),k=1...K
				kaggreMul=kaggreMul.mul(ti[i].duplicate().powZn(chal[i].random));
			}
		}	
		//����֤��
		Map<String,Object>proof=new HashMap<String,Object>(5);	    
		proof.put("ksaggreSum", ksaggreSum);
		proof.put("kaggreMul", kaggreMul);				
		return proof;
	}
	/**
	 * ����CSP������Proof,У������֤Proof�Ƿ���ȷ
	 * @param R MHT��Rootֵ����Ӧ������ս��Ĺ�ϣ���丨�����������R
	 * @param v ��Կ
	 * @param sigHashRoot ǩ������MHT��H(R)
	 * @return  true��false
	 */
	public boolean proofVerify(byte[]R,Element v,Element[]us,Chal[]chal,Map<String,Object>proof){

		int s=us.length;	
		Element aggreMul=(Element)proof.get("aggreMul");
		Element[] sAggreSum=(Element[])(proof.get("sAggreSum"));
		Element sigHashRoot=(Element)proof.get("sigHashRoot");
		Element[] Hmi=(Element[])proof.get("Hmi");
		//R<-genRoot(Element[] HashM,Qi)
		Element hashR=pairing.getG1().newElementFromHash(R, 0, R.length);
		Element temp1 = pairing.pairing(sigHashRoot, g);	
		Element temp2 = pairing.pairing(hashR, v);	


		//h(mi)^vi
		int c=Hmi.length;
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){			
			Element tmp=Hmi[i].duplicate().powZn(chal[i].random);
			aggreBlock=aggreBlock.duplicate().mul(tmp);
		}

		//��u^��
		Element u_=pairing.getG1().newOneElement();
		for(int j=0;j<s;j++){					
			u_=u_.mul(us[j].duplicate().powZn(sAggreSum[j]));
		}
		Element l=aggreBlock.duplicate().mul(u_);	    
		Element temp3 =pairing.pairing(aggreMul, g);		
		Element temp4 = pairing.pairing(l, v);	
		return (temp1.equals(temp2)&&temp3.equals(temp4))? true :false;

	}
	/**
	 * ������֤K���û���������֤��
	 * @param challenges k����ս�ļ���
	 * @param kRoot	  k��MHT����ֵ
	 * @param kv	  k����Կ
	 * @param kus	  k���û����ɱ�ǩ������ֵ 
	 * @param proof		֤��
	 * @return
	 */
	public boolean proofBathVerify(List<Chal[]>challenges,BigInteger []kRoot,Element[] kv,List<Element[]> kus,Map<String,Object>proof){
		//Element ksigHashRootAggre=(Element)proof.get("ksigHashRootAggre");
		Element[] ksigHashRoot=(Element[])proof.get("ksigHashRoot");
		List<Element[]>kHmi=(List<Element[]>)proof.get("kHmi");
		Element kaggreMul=(Element)proof.get("kaggreMul");
		List<Element[]> ksaggreSum=(List<Element[]>)proof.get("ksaggreSum");

		//��һ��֤K��MHT��R��һ������ͽ���
		//boolean MHTR=true;
		int K=challenges.size();		
		for(int k=0;k<K;k++){
			byte[] data=kRoot[k].toByteArray();
			Element hashR=pairing.getG1().newElementFromHash(data, 0, data.length);
			Element temp1 = pairing.pairing(ksigHashRoot[k], g);
			Element temp2 = pairing.pairing(hashR, kv[k]);	
			if(!temp1.equals(temp2)){
				StdOut.println("MHT_Root��֤����");
				//MHTR=false;
				return false;
			}
		}
		/*//�ۻ���֤K��MHT��R
		int K=kv.length;		
		Element temp2=pairing.getGT().newOneElement();
		for(int k=0;k<K;k++){
			byte[] data=kRoot[k].toByteArray();
			Element hashR=pairing.getG1().newElementFromHash(data, 0, data.length);
			temp2=temp2.mul(pairing.pairing(hashR, kv[k]));	
		}
		Element temp1=pairing.pairing(ksigHashRootAggre, g);*/

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

			//��u^��
			Element u_=pairing.getG1().newOneElement();
			Element []us=kus.get(k);
			Element []sAggreSum=ksaggreSum.get(k);
			int s=us.length;
			for(int j=0;j<s;j++){					
				u_=u_.duplicate().mul(us[j].duplicate().powZn(sAggreSum[j]));
			}			
			Element l=aggreBlock.duplicate().mul(u_);		
			temp4=temp4.duplicate().mul(pairing.pairing(l, kv[k]));	
		}
		Element temp3 =pairing.pairing(kaggreMul, g);		
		return temp3.equals(temp4)? true :false;

	}
	public Pairing getPairing() {
		return pairing;
	}	

}
