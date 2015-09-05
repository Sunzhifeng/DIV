package MHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.StdOut;
import tool.Stopwatch;
import MHT.MHTPADD_01.Chal;
import MHT.MerkleHashTree.Node;

/**
 * ����MHTPADD_01�Ĺ�������У�鹦��
 * @author MichaelSun
 *
 */
public class TestMHTPADD_01_bath {

	public static void main (String [] args) throws Exception{
		String fileName="readFileBlock.txt";
		int blockSize=4;//��kΪ��λ			
		int K=2;		//һ�ζ������û����ļ�����У��
		int [] kc={6,6};//ÿ����ս��Ϊ6��
		//��ʱ��
		Stopwatch start=new  Stopwatch();
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		MHTPADD_01 mhtPDP=new MHTPADD_01(false,"pairing/e/e.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//��ʼ����
		StdOut.println("-------------��ʼ����������------------");
		mhtPDP.setup();


		//���ļ�����Ԥ����
		StdOut.println("\n-------------���ļ�Ԥ����------------");
		Element[] pdata=fileOper.preProcessFile(fileName,blockSize, mhtPDP.getPairing().getZr());
		//StdOut.println("H(mi)->g��");
		Element[] gdata=mhtPDP.allGElement(pdata);
		int fileBlocks=pdata.length;
		//Element[] pdata=mhtPDP.allFieldElement(data);
		StdOut.println("�ļ�Ԥ�����ʱ��"+start.elapsedTime()+"ms");

		//����MHT
		MerkleHashTree mht=new MerkleHashTree(gdata);
		byte[] Root=mht.createMHT();
		StdOut.println(new BigInteger(Root));

		Map<Integer,Map<String,Element>> userKeys=new HashMap<Integer,Map<String,Element>>(K);
		Element []ku=new Element[K];
		Element[][]kblockTags=new Element[K][fileBlocks];
		Element[] ksigHashRoot=new Element[K];

		StdOut.println("\n-------------"+K+"���û�����Ԫ��Ϣ------------");
		Stopwatch dataOwnerTime=new Stopwatch();
		for(int k=0;k<K;k++){
			userKeys.put(k, mhtPDP.keyGen());//��Կ����		
			ku[k]=mhtPDP.genRandomU();//�û�����ֵ

			//Ԫ��������				
			for(int i=0;i<fileBlocks;i++){		
				kblockTags[k][i]=mhtPDP.metaGen(i,pdata[i],gdata[i],userKeys.get(k).get(MHTPADD_01.SECRETKEY),ku[k]);
			}
			ksigHashRoot[k]=mhtPDP.sigRoot(Root, userKeys.get(k).get(MHTPADD_01.SECRETKEY));

		}
		StdOut.println("DO��ʱ��"+dataOwnerTime.elapsedTime()+"ms");
		

		StdOut.println("\n==============verifier==============\n");
		StdOut.println("\n-------------������ս��Ϣ------------");
		List<Chal[]> challenges=new ArrayList<Chal[]>(K);		
		for(int k=0;k<K;k++)
			challenges.add(mhtPDP.challengeGen(kc[k],fileBlocks));
		StdOut.println("\n-------------������ս------------");
		/*for(Chal chal:challenge){
			StdOut.println("(���ţ������): "+"("+chal.num+","+chal.random+")");
		}*/



		StdOut.println("\n==============Cloud Service Provider==============\n");
		
		Stopwatch cspTime=new Stopwatch();
		StdOut.println("-------------����֤��------------");	
		List<Element[]> kmi=new ArrayList<Element[]>(K);
		List<int[]> kblockNumChal=new ArrayList<int[]>(K);
		List<Element[]> kti=new ArrayList<Element[]>(K);
		List<Element[]> kHmi=new ArrayList<Element[]>(K);

		for(int k=0;k<K;k++){
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//��ս�Ŀ������
			int [] blockNumChal=new int[CBCounts]; 
			Element[] mi=new Element[CBCounts];
			Element[] ti=new Element[CBCounts];
			Element[] Hmi=new Element[CBCounts];
			for(int i=0;i<CBCounts;i++){
				blockNumChal[i]=chal[i].num;//1-n
				mi[i]=pdata[chal[i].num-1];
				ti[i]=kblockTags[k][chal[i].num-1];
				Hmi[i]=gdata[chal[i].num-1];
			}
			kmi.add(mi);
			kblockNumChal.add(blockNumChal);
			kti.add(ti);
			kHmi.add(Hmi);
		}

		List<Object> kaai=new ArrayList<Object>(K);
		//Element ksigHashRootAggre=mhtPDP.getPairing().getG1().newOneElement();
		for(int k=0;k<K;k++){
			kaai.add(mht.genChalAAI(kblockNumChal.get(k)));//���㸨�������ռ�
		//	ksigHashRootAggre=ksigHashRootAggre.mul(ksigHashRoot[k]);
		}
		//�����ۼӺͱ�ǩ�۳�
		Map<String,Object>proof=mhtPDP.genBathProof(challenges, kmi, kti);	
		proof.put("kaai",kaai);
		proof.put("kHmi",kHmi);//Hmi�е�ֵ˳���Ӧ����ս��ŵ�˳��
		//proof.put("ksigHashRootAggre",ksigHashRootAggre);	//�۳�MHT����ǩ��
		proof.put("ksigHashRoot", ksigHashRoot);
		StdOut.println(proof);
		StdOut.println("csp��ʱ��"+cspTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		
		Stopwatch verTime=new  Stopwatch();
		StdOut.println("-------------���㲢��֤Root------------");		
		BigInteger[] knewRoot=new BigInteger[K];
		BigInteger[] errorKNewRoot=new BigInteger[K];
		for(int k=0;k<K;k++){
			//У���߸��ݿ���Ϣ����Root			
			knewRoot[k]=new BigInteger(mht.getRootByAuxiliaryIndex((Map<String,Object>)kaai.get(k),kblockNumChal.get(k)));
			errorKNewRoot[k]=BigInteger.ONE;
		}

		StdOut.println("\n-------------��֤���ݿ�------------");
		//���֤��
		Element[] kPublicKeys=new Element[K];
		for(int k=0;k<K;k++){
			kPublicKeys[k]=userKeys.get(k).get(MHTPADD_01.PUBLICKEY);
		}
		boolean rTrue=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,ku,proof);
		boolean rFalse1=mhtPDP.proofBathVerify(challenges,errorKNewRoot,kPublicKeys,ku,proof);//MHT��root����
		Element T=(Element)proof.get("kaggreMul");
		proof.put("kaggreMul", T.twice());
		boolean rFalse2=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,ku,proof);
		
		StdOut.println("��ʱ��"+verTime.elapsedTime()+" ms.");		
		//��֤���
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------֤����Ч����������------------");
		StdOut.println("�ܺ�ʱ��"+start.elapsedTime()+" ms.");
	}

}
