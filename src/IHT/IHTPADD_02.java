/**
 * ����������
 * 1.���÷ǶԳƵ�˫����ӳ��
 * 2.���ô�ǩ��������������ϣ��
 * 3.�����������ݱ�ǩ�����۳ɣ��ɷ��������㣬��С��У���ߵļ�����
 * 4.�������˶����ݱ�ǩ�۳ɵĸĽ��汾
 * 5.����У��
 * 6.��������Ϣä������
 */

package IHT;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import DetectErrors.FindErrorBlock;
import IHT.IndexHashTable.Item;
import MHT.MHTPADD_03.Chal;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sigAlg.DSACoder;
import tool.GenerateRandom;
import tool.SortAlg;
import tool.StdOut;
/**
 * ����IndexHashTableʵ�ֵ�����У�鷽��
 * @author MichaelSun
 * @version 2.0
 * @date  2014.12.23
 * 
 */
public class IHTPADD_02 {
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";

	//�ռ���Ϣ���浽�ļ�
	public  static Map<String,String> publicInfor=new LinkedHashMap<String,String>();
	public 	static Map<String,String> doPrivate=new LinkedHashMap<String,String>();
	public  static Map<String,String> verInfor=new LinkedHashMap<String,String>();
	public  static Map<String,String> cspInfor=new LinkedHashMap<String,String>();

	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g1;
	private Element g2;	
	public  String fileId;			//У����Hid��Ҫ�ļ���

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
	public IHTPADD_02(boolean usePBC, String curvePath) {
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
		g2 = pairing.getG2().newRandomElement().getImmutable();
		
		//publicInfor.put("pairing", pairing.toString());
		publicInfor.put("g1", g1.duplicate().toString());		
		publicInfor.put("g2", g2.duplicate().toString());

	}
	/**
	 * ���ɳ�ʼ����Կ
	 * @return
	 */
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);

		//������Կx
		Element x = pairing.getZr().newRandomElement().getImmutable();	
		doPrivate.put("a"+0, x.duplicate().toString());
		//���ɹ�Կpk
		Element v = g2.duplicate().powZn(x);
		publicInfor.put("v", v.duplicate().toString());
		verInfor.put("v", v.duplicate().toString());

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
		doPrivate.put("fileTag", sigFileMeta);
		cspInfor.put("fileTag", sigFileMeta);
		return (data+sigFileMeta).getBytes();
	}

	/**
	 * ����ָ��s��G��Ԫ��
	 * @param ps
	 */
	public Element[] usGen(Element[] ps){//����У���ǩʱ���ټ��㿪��
		int s=ps.length;
		Element []us=new Element[s];		
		for(int i=0;i<s;i++){			
			//ui=g1^ai
			us[i]=g1.duplicate().powZn(ps[i]);
			doPrivate.put("u"+(i+1), us[i].duplicate().toString());
			cspInfor.put("u"+(i+1), us[i].duplicate().toString());//�Ʒ�����Ҫu1......us
		}
		return us;
	}
	/**
	 * �������s��Zp��Ԫ��
	 * @param s
	 * @return
	 */
	public Element[] psGen(int s){
		Element [] ps=new Element[s];
		for(int i=0;i<s;i++){
			//a1,...as
			ps[i]=pairing.getZr().newRandomElement();
			doPrivate.put("a"+(i+1),ps[i].duplicate().toString());
		}
		return ps;
	}

	public Element hashKeyGen(Element[] ps,Element x){
		int s=ps.length;
		Element hashKey =pairing.getZr().newZeroElement();
		for(int i=0;i<s;i++){
			hashKey=hashKey.duplicate().add(ps[i]);
		}
		hashKey=hashKey.duplicate().add(x);
		return hashKey;
	}

	/**
	 * У���߲�����ս�������
	 * @return	Zp�е������
	 */
	public Element rGen(){
		Element r= pairing.getZr().newRandomElement();
		verInfor.put("r", r.duplicate().toString());
		return r;
	}
	/**
	 * ���ɵĿ��ǩ
	 * @param blockNum 	�ļ�����
	 * @param Hid		��������Ϣӳ�䵽G��Ԫ��
	 * @param x			��Կ
	 * @param mij		���еĶ�Ԫ������
	 * @return			�ļ����ǩ
	 */
	public Element metaGen(int blockNum,Element Hid,Element x,Element[]mij,Element []ps){
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
	 * У����������ս��Ϣ
	 * @param c   			У�����
	 * @param allBlocks   	ȫ������
	 * @param v				��Կ
	 * @return				��ս��ϢChallengeR
	 */
	public Map<String,Object> challengeGen(int c,int allBlocks,Element v,Element r,String fileId){
		int []ran=new int[c];
		ran=GenerateRandom.random(1,allBlocks,c); //1-allBlocks�е�c����ͬ����
		SortAlg.sort(ran, 0, c-1);
		Chal[]challenge=new Chal[c];		
		//����ÿ���Ӧ�������vi
		for(int i=0;i<c;i++){			
			challenge[i]=new Chal(ran[i],pairing.getZr().newRandomElement());
		}		
		Element R=v.duplicate().powZn(r);//!!!�����v��Կ����duplicate
		this.fileId=fileId;	
		Map<String,Object> challengeR=new HashMap<String,Object>(2);
		challengeR.put("challenge", challenge);
		challengeR.put("R", R);	
		return challengeR;
	}

	//�Ľ���ս�Ĵ�������������+һ������������Ĺ�ϣ��Կk1
	public Map<String,Object>  challengeGen2(int c,int allBlocks,Element v,Element r,String fileId){
		int []blocknum=new int[c];			
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();
		BigInteger k2=pairing.getZr().newRandomElement().toBigInteger();//���ɿ�ŵ�����
		blocknum=GenerateRandom.random(1,allBlocks,c,k2.longValue()); //1-allBlocks�е�c����ͬ����

		//k1����hash����Կ������ÿ���Ӧ�������vi
		Element[]vi=randomVi(c,blocknum,k1,pairing.getZr());
		Element R=v.duplicate().powZn(r);//!!!�����v��Կ����duplicate
		this.fileId=fileId;	
		Map<String,Object> challengeKR=new HashMap<String,Object>(2);
		challengeKR.put("vi", vi);
		challengeKR.put("blocknum", blocknum);//���ݿ�ı��
		challengeKR.put("R", R);
		challengeKR.put("k1", k1);

		verInfor.put("blocknum",intsToString(blocknum));
		verInfor.put("R", R.toString());
		verInfor.put("vi", elementsToString(vi));
		verInfor.put("k1", k1.toString());

		return challengeKR ;
	}
	//���ԶԹ̶���������ж����ս������ʱ������
	public Map<String,Object>  challengeGen3(int[] samplec,int start,int end,Element v,Element r,String fileId){

		int c=end-start+1;
		int [] blocknum=new int[c];
		for(int j=0;j<c;j++){
			blocknum[j]=samplec[start+j-1];
		}
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();

		//k1����hash����Կ������ÿ���Ӧ�������vi
		Element[]vi=randomVi(c,blocknum,k1,pairing.getZr());
		Element R=v.duplicate().powZn(r);
		this.fileId=fileId;	
		Map<String,Object> challengeKR=new HashMap<String,Object>(2);
		challengeKR.put("vi", vi);
		challengeKR.put("blocknum", blocknum);
		challengeKR.put("R", R);
		challengeKR.put("k1", k1);

		verInfor.put("blocknum",intsToString(blocknum));
		verInfor.put("R", R.toString());
		verInfor.put("vi", elementsToString(vi));
		verInfor.put("k1", k1.toString());

		return challengeKR ;
	}


	//�����������þ���ķ�ʽ������ս
	public Map<String,Object>  challengeGen4(int [] blocknum,Element v,Element r,String fileId){
		int c=blocknum.length;	

		//k1����hash����Կ������ÿ���Ӧ�������vi
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();
		Element[]vi=randomVi(c,blocknum,k1,pairing.getZr());
		Element R=v.duplicate().powZn(r);//!!!�����v��Կ����duplicate
		this.fileId=fileId;	

		//��þ��������		
		Map<String,Integer> mab=FindErrorBlock.getMatrixIndex(c);

		Map<String,Object> challengeKR=new HashMap<String,Object>(2);
		challengeKR.put("vi", vi);
		challengeKR.put("blocknum", blocknum);//���ݿ�ı��
		challengeKR.put("R", R);
		challengeKR.put("k1", k1);
		challengeKR.put("row", mab.get("row"));
		challengeKR.put("col", mab.get("col"));

		verInfor.put("blocknum",intsToString(blocknum));
		verInfor.put("R", R.toString());
		verInfor.put("vi", elementsToString(vi));
		verInfor.put("k1", k1.toString());
		verInfor.put("row", mab.get("row").toString());
		verInfor.put("col", mab.get("col").toString());		
		return challengeKR ;
	}
	//����c����ս���Ӧ�������
	public Element[] randomVi(int c,int[] blocknum,BigInteger k1,Field Zp){
		Element []vi=new Element[c];
		for(int i=0;i<c;i++){
			vi[i]=Zp.newElement(k1.add(BigInteger.valueOf(blocknum[i])));

		}
		return vi;
	}


	/**
	 * CSP��������������֤��proof�������ݱ�ǩ�۳�
	 * @param vi ÿ����ս���Ӧ�������	
	 * @param ti ÿ�����Ԫ��ǩ	
	 * @param R  ��ս��ʱ���
	 * @return
	 */
	public Map<String,Object> genProof(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		//�������ʱ����һ�����⣺ÿ�����ģ�����㣬���Ƕ���ͽ������ģ�����㣬��ʱ��ȡǰ��
		int s=us.length;
		int c=vi.length;			
		Element aggreTMul=pairing.getG1().newOneElement();//���ǩ�۳�
		Element aggreDMul=pairing.getGT().newOneElement();//���ݿ��۳�
		Element aggreSum;
		//���ݿ���۳�
		for(int k=0;k<s;k++){
			aggreSum=pairing.getZr().newZeroElement();//ÿ����������һ����ʼ0Ԫ��
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][k]));
			}	
			//��(e(uj,R)^MPj)
			aggreDMul=aggreDMul.mul(pairing.pairing(us[k].duplicate(),R.duplicate()).powZn(aggreSum));
		}
		//���ݱ�ǩ���۳�
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}
		//ȫ�ֱ���proof������Ϣ
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);		
		return proof;


	}

	//����֤�����ɡ�(e(uj,R)^MPj)->e(��uj^MPj,R)	
	public Map<String,Object> genProof2(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		//�������ʱ����һ�����⣺ÿ�����ģ�����㣬���Ƕ���ͽ������ģ�����㣬��ʱ��ȡǰ��
		int s=us.length;
		int c=vi.length;			

		Element aggreTMul=pairing.getG1().newOneElement();//���ǩ�۳�
		Element aggreDMulTemp=pairing.getG1().newOneElement();//���ݿ��۳�
		Element aggreSum;
		//���ݿ���۳�
		for(int k=0;k<s;k++){
			aggreSum=pairing.getZr().newZeroElement();//ÿ����������һ����ʼ0Ԫ��
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][k]));
			}
			//��uj^MPj
			aggreDMulTemp=aggreDMulTemp.mul(us[k].duplicate().powZn(aggreSum));
		}
		//e(��uj^MPj,R)
		Element aggreDMul=pairing.pairing(aggreDMulTemp, R.duplicate());
		//���ݱ�ǩ���۳�
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//ȫ�ֱ���proof������Ϣ
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);	
		return proof;

	}

	//��������ݽ���ä������
	public Map<String,Object> genProof3(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		int s=us.length;
		int c=vi.length;
		Element [] a=new Element[s];//CSP����Ϣä��������������ֵ
		Element [] b=new Element[s];//���ui^ai
		Element aggreTMul=pairing.getG1().newOneElement();//���ǩ�۳�
		Element aggreDMulTemp=pairing.getG1().newOneElement();//���ݿ��۳�
		Element aggreRanMulTemp=pairing.getG1().newOneElement();//ä�������ֵ��۳�
		Element aggreSum;
		//���ݿ���۳�
		for(int j=0;j<s;j++){
			//ä����Ϣ����aj<-Zp;bj<-usj^aj;h(bj)->Zp
			a[j]=pairing.getZr().newRandomElement();
			b[j]=us[j].duplicate().powZn(a[j]);
			//Element hb=pairing.getZr().newElementFromBytes(b[j].toBytes());//��Ҫ��hashӳ�䣿
			Element hb=pairing.getZr().newElementFromHash(b[j].toBytes(),0,b[j].toBytes().length);//��hashӳ��
			Element ahb=a[j].mul(hb);
			//��bj^h(bj)
			aggreRanMulTemp=aggreRanMulTemp.mul(b[j].duplicate().powZn(hb));
			aggreSum=pairing.getZr().newZeroElement();//ÿ����������һ����ʼ0Ԫ��
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][j]));
			}			
			aggreSum=aggreSum.add(ahb);
			//��uj^MPj
			aggreDMulTemp=aggreDMulTemp.mul(us[j].duplicate().powZn(aggreSum));
		}
		//e(��uj^MPj,R)
		Element aggreDMul=pairing.pairing(aggreDMulTemp, R.duplicate());
		Element aggreRanMul=pairing.pairing(aggreRanMulTemp, R.duplicate());

		//���ݱ�ǩ���۳�
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//ȫ�ֱ���proof������Ϣ
		Map<String,Object> proof=new HashMap<String,Object>(4);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);
		proof.put("aggreRanMul",aggreRanMul);
		return proof;

	}
	//ä������2
	public Map<String,Object> genProof4(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		int s=us.length;
		int c=vi.length;
		Element a=pairing.getZr().newRandomElement();;//CSP����Ϣä��������������ֵ
		Element b=us[new Random().nextInt(s)].duplicate().powZn(a);//���ui^a
		Element aggreTMul=pairing.getG1().newOneElement();//���ǩ�۳�
		Element aggreDMulTemp=pairing.getG1().newOneElement();//���ݿ��۳�
		Element aggreSum;
		//���ݿ���۳�
		for(int j=0;j<s;j++){
			aggreSum=pairing.getZr().newZeroElement();//ÿ����������һ����ʼ0Ԫ��
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][j]));
			}			
			//��uj^MPj
			aggreDMulTemp=aggreDMulTemp.mul(us[j].duplicate().powZn(aggreSum));
		}
		//e((��uj^MPj)*b,R)
		Element aggreDMul=pairing.pairing(aggreDMulTemp.mul(b), R.duplicate());
		//e(b,R)
		Element aggreRanMul=pairing.pairing(b, R.duplicate());

		//���ݱ�ǩ���۳�
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//ȫ�ֱ���proof������Ϣ
		Map<String,Object> proof=new HashMap<String,Object>(4);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);
		proof.put("aggreRanMul",aggreRanMul);
		return proof;

	}

  
	//����У��
	public Map<String,Object> genBathProof(List<Map<String,Object>>kchallengeRs,List<Element[][]> kmij,List<Element[]> kti,List<Element[]>kus,int s){
		int K=kchallengeRs.size();						
		Element kaggreTMul=pairing.getG1().newOneElement();	
		Element kaggreDMul=pairing.getGT().newOneElement();//k�����ݿ��۳�

		for(int k=0;k<K;k++){
			Map<String,Object>challengeRs=kchallengeRs.get(k);
			Chal []challenge=(Chal[])challengeRs.get("challenge");
			int CBCounts=challenge.length;
			Element R=(Element)challengeRs.get("R");
			Element[][] mij=kmij.get(k);	//��k����ս�Ķμ���
			Element[]us=kus.get(k);			//��k����ս�ı�ǩ���������
			Element aggreDMulTemp=pairing.getG1().newOneElement();//���ݿ��۳�

			//���ݿ���۳�
			for(int j=0;j<s;j++){
				Element aggreSum=pairing.getZr().newZeroElement();//ÿ����������һ����ʼ0Ԫ��
				for(int i=0;i<CBCounts;i++){				
					//sum(vi*mij)
					aggreSum=aggreSum.add(challenge[i].random.duplicate().mulZn(mij[i][j]));
				}
				//��uj^MPj
				aggreDMulTemp=aggreDMulTemp.mul(us[j].duplicate().powZn(aggreSum));
			}
			//e(��uj^MPj,R)
			kaggreDMul=kaggreDMul.mul(pairing.pairing(aggreDMulTemp, R.duplicate()));

			//���ݱ�ǩ���۳�
			Element aggreTMul=pairing.getG1().newOneElement();//���ǩ�۳�
			Element[]ti=kti.get(k);			//��k����ս�Ŀ��ǩ�ļ���
			for(int i=0;i<CBCounts;i++){			
				//mul(ti^vi)
				aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(challenge[i].random));
			}
			kaggreTMul=kaggreTMul.mul(aggreTMul);
		}
		//ȫ�ֱ���proof������Ϣ
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("kaggreDMul", kaggreDMul);
		proof.put("kaggreTMul", kaggreTMul);	
		return proof;

	}

	/**
	 * ����CSP������Proof,У������֤Proof�Ƿ���ȷ	
	 * @param v ��Կ	
	 * @return  true��false
	 */
	public boolean proofVerify(Element v,Element r,Map<String,Object> challengeR ,Map<String,Object> proof,String fileId){
		Chal[] challenge=(Chal[])challengeR.get("challenge");		
		Element aggreTMul=(Element)proof.get("aggreTMul");
		Element aggreDMul=(Element)(proof.get("aggreDMul"));
		Item[] id=(Item[])proof.get("id");//��ս���������ϣ��Ŀ����
		Element aggreRanMul=(Element)proof.get("aggreRanMul");
		//Hchal=h(Idi)^(r*vi)
		int c=id.length;		
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
			Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
			Element tmp=Hid.powZn(r.duplicate().mulZn(challenge[i].random));
			aggreBlock=aggreBlock.mul(tmp);
		}	
		//e(Hchal,v)	
		Element temp1 =pairing.pairing(aggreBlock,v);	
		//e(Tp,g2^r)
		Element temp2 = pairing.pairing(aggreTMul, g2.powZn(r));
		return (aggreDMul.mul(temp1)).equals(aggreRanMul.mul(temp2))? true :false;//ä����Ϣ����

	}

	//��ս����Q,k1,R)����֤�ݽ�����֤
	public boolean proofVerify2(Element v,Element r,Map<String,Object> challengeKR ,Map<String,Object> proof,String fileId){

		//int[] blocknum=(int [])challengeKR.get("blocknum");
		Element[] vi=(Element[])challengeKR.get("vi");	
		Element aggreTMul=(Element)proof.get("aggreTMul");
		Element aggreDMul=(Element)(proof.get("aggreDMul"));
		Item[] id=(Item[])proof.get("id");//��ս���������ϣ��Ŀ����
		Element aggreRanMul=(Element)proof.get("aggreRanMul");

		//Hchal=h(Idi)^(r*vi)
		int c=id.length;		
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
			Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
			Element tmp=Hid.powZn(r.duplicate().mulZn(vi[i]));
			aggreBlock=aggreBlock.mul(tmp);
		}

		//e(Hchal,v)	
		Element temp1 =pairing.pairing(aggreBlock,v);

		//e(Tp,g2^r)
		Element temp2 = pairing.pairing(aggreTMul, g2.powZn(r));
		return (aggreDMul.mul(temp1)).equals(aggreRanMul.mul(temp2))? true :false;//ä����Ϣ����

	}


	public boolean proofBathVerify(Element[] kv,Element r,List<Map<String,Object>> kchallengeRs ,Map<String,Object> proof,String fileId){//���ҿ������е�fileId��ͬ

		int K =kchallengeRs.size();
		Element kaggreTMul=(Element)proof.get("kaggreTMul");
		Element kaggreDMul=(Element)(proof.get("kaggreDMul"));
		Element keaggreMul=pairing.getGT().newOneElement();

		for(int k=0;k<K;k++){
			Chal[] challenge=(Chal[])kchallengeRs.get(k).get("challenge");
			Item[] id=((List<Item[]>)proof.get("kid")).get(k);//��k����ս���������ϣ��Ŀ����
			int CBCounts=challenge.length;		
			Element aggreBlock=pairing.getG1().newOneElement();

			//Hchal=h(Idi)^(r*vi)
			for(int i=0;i<CBCounts;i++){
				byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
				Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
				Element tmp=Hid.powZn(r.duplicate().mulZn(challenge[i].random));
				aggreBlock=aggreBlock.mul(tmp);
			}
			//��e(Hchal,v)	
			keaggreMul=keaggreMul.mul(pairing.pairing(aggreBlock,kv[k]));
		}	

		//e(kTp,g2^r)
		Element temp2 = pairing.pairing(kaggreTMul, g2.powZn(r));
		return (kaggreDMul.mul(keaggreMul)).equals(temp2)? true :false;

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

	//��Element[]����ת���ɸ�ʽ�����ַ����Ա㷽��������ļ�
	public static String elementsToString(Element[] e){
		int len=e.length;
		String result=e[0].duplicate().toBigInteger().toString();
		for(int i=1;i<len-1;i++)
			result+=" "+e[i].duplicate().toBigInteger().toString();
		return result;
	}

	public static String intsToString(int [] a){
		int len=a.length;
		String result=Integer.toString(a[0]);
		for(int i=1;i<len;i++){
			result+=" "+Integer.toString(a[i]);
		}
		return result;

	}

	

	public Pairing getPairing() {
		return pairing;
	}	




}
