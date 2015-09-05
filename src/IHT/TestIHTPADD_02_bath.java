package IHT;

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

import IHT.IHTPADD_02.Chal;
import IHT.IndexHashTable.Item;
import tool.StdOut;
import tool.Stopwatch;

/**
 * ����MHTPADD_02�Ĺ�������У�鹦��
 * @author MichaelSun
 *
 */
public class TestIHTPADD_02_bath {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";
		int s=200;				//ÿ��Ķ���
		int sectorSize=20;		//160bit
		int blockSize=s*sectorSize/1000;//��kΪ��λ				
		int K=2;		//һ�ζ������û����ļ�����У��
		int [] kc={23,23};//ÿ����ս��Ϊ6��
		//��ʱ��
		Stopwatch start=new  Stopwatch();
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		IHTPADD_02 ihtPADD=new IHTPADD_02(false,"pairing/d/d_159.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//��ʼ����
		StdOut.println("-------------��ʼ����������------------");
		ihtPADD.setup();

		//������Կ�����ֵ
		Map<Integer,Map<String,Element>> userKeys=new HashMap<Integer,Map<String,Element>>(K);
		List<Element []>kus=new ArrayList<Element[]>(K);
		List<Element []>kps=new ArrayList<Element[]>(K);
		for(int k=0;k<K;k++){
			userKeys.put(k, ihtPADD.keyGen());//��Կ����			
			kps.add(ihtPADD.psGen(s));
			kus.add(ihtPADD.usGen(kps.get(k)));//�û�����ֵ			
		}
		List<Element> hashKeys=new ArrayList<Element>(K);
		for(int j=0;j<K;j++){
			hashKeys.add(ihtPADD.hashKeyGen(kps.get(j),userKeys.get(j).get(ihtPADD.SECRETKEY)));
		}

		//���ļ�����Ԥ����
		StdOut.println("\n-------------���ļ�Ԥ����------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, ihtPADD.getPairing().getZr());
		Element[][] sectors=HDFSFileOperation.sectors;
		//Element[] gdata=ihtPADD.allGElement(pdata);		
		int fileBlocks=pdata.length;		
		StdOut.println("�ļ�Ԥ�����ʱ��"+start.elapsedTime()+"ms");

		StdOut.println("\n-------------����������ϣ��------------");
		IndexHashTable[] ihtables=new IndexHashTable[K];
		List<Item[]> kItems=new ArrayList<Item[]>(K);
		for(int k=0;k<K;k++){		
			
			//����������ϣ��IHT
			ihtables[k]=new IndexHashTable(fileName,fileBlocks);			
			kItems.add(ihtables[k].createIHT2(ihtPADD.getPairing().getZr(),hashKeys.get(k) , ihtPADD.getPairing().getG1(),pdata));		
			
		}
		StdOut.println("\n-------------"+K+"���û�����Ԫ��Ϣ------------");
		Stopwatch dataOwnerTime=new Stopwatch();
		Element[][]kblockTags=new Element[K][fileBlocks];		
		for(int k=0;k<K;k++){			
			Element[] Hid=ihtables[k].getHids();//Hid��0λ�ô�ŵ���ZeroElement
			//Ԫ��������				
			for(int i=0;i<fileBlocks;i++){		
				kblockTags[k][i]=ihtPADD.metaGen(i,Hid[i+1],userKeys.get(k).get(ihtPADD.SECRETKEY),sectors[i],kps.get(k));
			}

		}
		StdOut.println("DO��ʱ��"+dataOwnerTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		StdOut.println("\n-------------������ս��Ϣ------------");
		List<Map<String,Object>> kchallengeRs=new ArrayList<Map<String,Object>>(K);		
		Element r=ihtPADD.rGen();//һ��У���Ӧһ��r
		for(int k=0;k<K;k++){		
			kchallengeRs.add(ihtPADD.challengeGen(kc[k],fileBlocks,userKeys.get(k).get(ihtPADD.PUBLICKEY),r,fileName));
		}
		StdOut.println("\n-------------������ս------------");



		StdOut.println("\n==============Cloud Service Provider==============\n");

		Stopwatch cspTime=new Stopwatch();
		StdOut.println("-------------����֤��------------");	
		List<Element[][]> kmij=new ArrayList<Element[][]>(K);		
		List<Element[]> kti=new ArrayList<Element[]>(K);
		List<Item[]> kid=new ArrayList<Item[]>(K);
		//����������ս��Ԫ��Ϣ���д���
		for(int k=0;k<K;k++){
			Chal[] chal=(Chal[])kchallengeRs.get(k).get("challenge");
			int CBCounts=chal.length;//��ս�Ŀ������
			Item [] item=kItems.get(k);
			Element[][] mij=new Element[CBCounts][s];
			Element[] ti=new Element[CBCounts];	
			Item[] id=new Item[CBCounts];
			for(int i=0;i<CBCounts;i++){					
				ti[i]=kblockTags[k][chal[i].num-1];
				id[i]=item[chal[i].num];
				for(int j=0;j<s;j++){
					mij[i][j]=sectors[chal[i].num-1][j];//��ȡ����
				}
				
			}
			kmij.add(mij);			
			kti.add(ti);
			kid.add(id);
		}

		//�����ۼӺͱ�ǩ�۳�
		Map<String,Object>proof=ihtPADD.genBathProof(kchallengeRs, kmij, kti,kus,s);	
		proof.put("kid", kid);
		StdOut.println(proof);
		StdOut.println("csp��ʱ��"+cspTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		Stopwatch verTime=new  Stopwatch();	
		StdOut.println("\n-------------��֤֤��------------");
		//���֤��
		Element[] kPublicKeys=new Element[K];
		for(int k=0;k<K;k++){
			kPublicKeys[k]=userKeys.get(k).get(IHTPADD_02.PUBLICKEY);
		}
		boolean rTrue=ihtPADD.proofBathVerify(kPublicKeys,r,kchallengeRs,proof,fileName);
		boolean rFalse1=ihtPADD.proofBathVerify(kPublicKeys,r.duplicate().twice(),kchallengeRs,proof,fileName);//MHT��root����
		Element D=(Element)proof.get("kaggreDMul");
		proof.put("kaggreDMul", D.twice());
		boolean rFalse2=ihtPADD.proofBathVerify(kPublicKeys,r,kchallengeRs,proof,fileName);

		StdOut.println("��ʱ��"+verTime.elapsedTime()+" ms.");		
		//��֤���
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------֤����Ч����������------------");
		StdOut.println("�ܺ�ʱ��"+start.elapsedTime()+" ms.");
	}

}
