package MHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.StdOut;
import tool.Stopwatch;
import MHT.MHTPADD_01.Chal;

/**
 * ����MHTPADD_01�Ĺ���
 * @author MichaelSun
 *
 */
public class TestMHTPADD_01 {

	public static void main (String [] args) throws Exception{
		String fileName="readFileBlock.txt";
		int blockSize=4;//��kΪ��λ
		int c=3;	

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
		Element[] gdata=mhtPDP.allGElement(pdata);
		int fileBlocks=pdata.length;	
		StdOut.println("�ļ�Ԥ�����ʱ��"+start.elapsedTime()+"ms");

		StdOut.println("\n-------------������Կ------------");
		//��Կ����
		Map<String,Element> keyMap=mhtPDP.keyGen();	        
		//�������ɱ�ǩ�����ֵ
		Element u=mhtPDP.genRandomU();
		//Ԫ��������
		Element[] blockTags=new Element[fileBlocks];
		StdOut.println("\n-------------����ÿ��ı�ǩ------------");
		Stopwatch tagTime=new Stopwatch();
		for(int i=0;i<fileBlocks;i++){		
			blockTags[i]=mhtPDP.metaGen(i,pdata[i],gdata[i],keyMap.get(MHTPADD_01.SECRETKEY),u);
			//StdOut.println((i+1)+"���ǩ��"+new String(Hex.encode(blockTags[i].toBytes())));
		}
		StdOut.println("��ǩ���ɺ�ʱ��"+tagTime.elapsedTime()+"ms");

		//����MHT������Root����ǩ��,ǩ������512*4=2048bit
		MerkleHashTree mht=new MerkleHashTree(gdata);
		byte[] Root=mht.createMHT();				
		Element sigHashRoot=mhtPDP.sigRoot(Root, keyMap.get(MHTPADD_01.SECRETKEY));
		StdOut.println("\n-------------������ϣ��������������ǩ��------------");
		//StdOut.println("root��"+new String(Hex.encode(Root)));
		//StdOut.println("sigRoot��"+new String(Hex.encode(sigRoot.toBytes())));

		
		StdOut.println("\n==============verifier==============\n");
		StdOut.println("\n-------------������ս��Ϣ------------");
		Stopwatch challengeTime=new Stopwatch();			
		Chal [] challenge=mhtPDP.challengeGen2(c,fileBlocks);
		StdOut.println("��ս��Ϣ��ʱ��"+challengeTime.elapsedTime()+"ms");	
		StdOut.println("\n-------------������ս------------");		


		StdOut.println("\n==============Cloud Service Provider==============\n");
		
		//������������ս��Ϣ�����֤�ݵ�Ԫ����
		int [] blockNumChall=new int[c];//���
		Element [] vi=new Element[c];//�����
		Element [] mi=new Element[c];
		Element [] ti=new Element[c];//���ǩ	
		Element [] Hmi =new Element[c];
		for(int i=0;i<c;i++){
			blockNumChall[i]=challenge[i].num;
			vi[i]=challenge[i].random;
			ti[i]=blockTags[challenge[i].num-1];
			mi[i]=pdata[challenge[i].num-1];	//ʵ��������pdata������������		
			Hmi[i]=gdata[challenge[i].num-1];	//ʵ����HmiӦ���ɷ��������¼���		
		}
		
		StdOut.println("-------------����֤��------------");
		Stopwatch genProofTime =new Stopwatch();
		//����������֤��		
		Map<String,Object> aai=mht.genChalAAI(blockNumChall);//���㸨�������ռ� 
		Map<String,Object>proof=mhtPDP.genProof(vi, mi, ti);				
		proof.put("AAI",aai);
		proof.put("Hmi",Hmi);//Hmi�е�ֵ˳���Ӧ����ս��ŵ�˳��
		proof.put("sigHashRoot", sigHashRoot);
		//StdOut.println(proof);
		StdOut.println("����֤�ݺ�ʱ��"+genProofTime.elapsedTime()+"ms");	



		StdOut.println("\n==============verifier==============\n");
		Stopwatch verProofTime=new Stopwatch();
		//У���߸��ݿ���Ϣ����Root
		byte[] newRoot=mht.getRootByAuxiliaryIndex(aai,blockNumChall);
		StdOut.println("-------------���㲢��֤Root����֤���ݿ�------------");

		//���֤��
		boolean rTrue=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_01.PUBLICKEY),u,challenge,proof);
		boolean rFalse2=mhtPDP.proofVerify(Root, keyMap.get(MHTPADD_01.PUBLICKEY).twice(),u,challenge,proof);
		proof.put("sigHashRoot", sigHashRoot.twice());
		boolean rFalse1=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_01.PUBLICKEY),u, challenge,proof);
		StdOut.println("��֤֤�ݺ�ʱ��"+verProofTime.elapsedTime()+"ms");	
	
		//��֤���
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------֤����Ч����������------------");
		StdOut.println("У������ܺ�ʱ��"+start.elapsedTime()+" ms.");
	}
}
