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
import MHT.MHTPADD_03.Chal;
import MHT.MerkleHashTree.Node;

/**
 * ����MHTPADD_02�Ĺ�������У�鹦��
 * @author MichaelSun
 *
 */
public class TestMHTPADD_03_bath {

	public static void main (String [] args) throws Exception{
		String fileName="readFileBlock.txt";
		int s=200;				//ÿ��Ķ���
		int sectorSize=20;		//160bit
		int blockSize=s*sectorSize/1000;//��kΪ��λ				
		int K=2;		//һ�ζ������û����ļ�����У��
		int [] kc={23,23};//ÿ����ս��Ϊ6��
		//��ʱ��
		Stopwatch start=new  Stopwatch();
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		MHTPADD_03 mhtPDP=new MHTPADD_03(false,"pairing/d/d_159.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//��ʼ����
		StdOut.println("-------------��ʼ����������------------");
		mhtPDP.setup();
		
		//������Կ�����ֵ
		Map<Integer,Map<String,Element>> userKeys=new HashMap<Integer,Map<String,Element>>(K);
		List<Element []>kus=new ArrayList<Element[]>(K);
		List<Element []>kps=new ArrayList<Element[]>(K);
		
		for(int k=0;k<K;k++){
			userKeys.put(k, mhtPDP.keyGen());//��Կ����
			Element[] ps=mhtPDP.psGen(s);
			kps.add(ps);
			kus.add(mhtPDP.usGen(ps));//�û�����ֵ
		}
		
		//���ļ�����Ԥ����
		StdOut.println("-------------���ļ�Ԥ����------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, mhtPDP.getPairing().getZr());
		Element[][] sectors=HDFSFileOperation.sectors;
		Element[] gdata=mhtPDP.allGElement(pdata);		
		int fileBlocks=pdata.length;		
		StdOut.println("�ļ�Ԥ�����ʱ��"+start.elapsedTime()+"ms");
		
		StdOut.println("-------------����MHT��------------");
		MerkleHashTree[] kmht=new MerkleHashTree[K];
		BigInteger[]kRoot=new BigInteger[K];
		for(int k=0;k<K;k++){
		//����MHT-����������ս��root��ͬ
		MerkleHashTree mht=new MerkleHashTree(gdata);
		kmht[k]=mht;
		kRoot[k]=new BigInteger(mht.createMHT());
		}
		StdOut.println("-------------����У��Ԫ��Ϣ------------");
		Stopwatch dataOwnerTime=new Stopwatch();
		Element[][]kblockTags=new Element[K][fileBlocks];
		Element[] ksigHashRoot=new Element[K];
		for(int k=0;k<K;k++){
			//Ԫ��������				
			for(int i=0;i<fileBlocks;i++){		
				kblockTags[k][i]=mhtPDP.metaGen(i,gdata[i],userKeys.get(k).get(MHTPADD_03.SECRETKEY),sectors[i],kps.get(k));
			}
			ksigHashRoot[k]=mhtPDP.sigRoot(kRoot[k].toByteArray(), userKeys.get(k).get(MHTPADD_03.SECRETKEY));

		}
		StdOut.println("DO��ʱ��"+dataOwnerTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		StdOut.println("-------------������ս��Ϣ------------");
		List<Chal[]> challenges=new ArrayList<Chal[]>(K);		
		for(int k=0;k<K;k++)
			challenges.add(mhtPDP.challengeGen(kc[k],fileBlocks));
		StdOut.println("-------------������ս------------");
		


		StdOut.println("\n==============Cloud Service Provider==============\n");

		Stopwatch cspTime=new Stopwatch();
		StdOut.println("-------------����֤��------------");	
		List<List<Element[]>> kmij=new ArrayList<List<Element[]>>(K);
		List<int[]> kblockNumChal=new ArrayList<int[]>(K);
		List<Element[]> kti=new ArrayList<Element[]>(K);
		List<Element[]> kHmi=new ArrayList<Element[]>(K);

		for(int k=0;k<K;k++){
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//��ս�Ŀ������
			int [] blockNumChal=new int[CBCounts]; 
			List<Element[]> mij=new ArrayList<Element[]>(CBCounts);
			Element[] ti=new Element[CBCounts];
			Element[] Hmi=new Element[CBCounts];
			for(int i=0;i<CBCounts;i++){
				Element[]mj=new Element[s];
				blockNumChal[i]=chal[i].num;//1-n			
				ti[i]=kblockTags[k][chal[i].num-1];
				Hmi[i]=gdata[chal[i].num-1];
				for(int j=0;j<s;j++){
					mj[j]=sectors[chal[i].num-1][j];//��ȡ����
				}
				mij.add(mj);
			}
			kmij.add(mij);
			kblockNumChal.add(blockNumChal);
			kti.add(ti);
			kHmi.add(Hmi);
		}

		List<Object> kaai=new ArrayList<Object>(K);
		//Element ksigHashRootAggre=mhtPDP.getPairing().getG1().newOneElement();
		for(int k=0;k<K;k++){
			kaai.add(kmht[k].genChalAAI(kblockNumChal.get(k)));//���㸨�������ռ�
				//ksigHashRootAggre=ksigHashRootAggre.mul(ksigHashRoot[k]);
		}
		//�����ۼӺͱ�ǩ�۳�
		Map<String,Object>proof=mhtPDP.genBathProof(challenges, kmij, kti,s);	
		proof.put("kaai",kaai);
		proof.put("kHmi",kHmi);//Hmi�е�ֵ˳���Ӧ����ս��ŵ�˳��
		//proof.put("ksigHashRootAggre",ksigHashRootAggre);	//�۳�MHT����ǩ��
		proof.put("ksigHashRoot", ksigHashRoot);
		StdOut.println(proof);
		StdOut.println("csp��ʱ��"+cspTime.elapsedTime()+"ms");


		StdOut.println("\n==============Verifier==============\n");

		Stopwatch verTime=new  Stopwatch();
		StdOut.println("-------------���㲢��֤Root------------");		
		BigInteger[] knewRoot=new BigInteger[K];
		BigInteger[] errorKNewRoot=new BigInteger[K];//����Ĳ�������
		for(int k=0;k<K;k++){
			//У���߸��ݿ���Ϣ����Root			
			knewRoot[k]=new BigInteger(kmht[k].getRootByAuxiliaryIndex((Map<String,Object>)kaai.get(k),kblockNumChal.get(k)));
			errorKNewRoot[k]=BigInteger.ONE;
		}

		StdOut.println("-------------��֤���ݿ�------------");
		//���֤��
		Element[] kPublicKeys=new Element[K];
		for(int k=0;k<K;k++){
			kPublicKeys[k]=userKeys.get(k).get(MHTPADD_03.PUBLICKEY);
		}
		boolean rTrue=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,kus,proof);
		boolean rFalse1=mhtPDP.proofBathVerify(challenges,errorKNewRoot,kPublicKeys,kus,proof);//MHT��root����
		Element T=(Element)proof.get("kaggreMul");
		proof.put("kaggreMul", T.twice());
		boolean rFalse2=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,kus,proof);

		StdOut.println("��ʱ��"+verTime.elapsedTime()+" ms.");		
		//��֤���
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("------------֤����Ч����������------------");
		StdOut.println("�ܺ�ʱ��"+start.elapsedTime()+" ms.");
	}

}
