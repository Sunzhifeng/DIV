package MHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.Sampling;
import tool.StdOut;
import tool.Stopwatch;
import MHT.MHTPADD_02.Chal;
import MHT.MerkleHashTree.Node;

/**
 * MHTPADD_02���в���
 * @author MichaelSun
 * @version 2.0
 * @date 2014.11.21
 */
public class TestMHTPADD_02 {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";	
		int c=30;					//��ս�Ŀ�����
		int s=100;				//ÿ��Ķ���
		int sectorSize=20;		//160bit
		int blockSize=s*sectorSize/1000;//��kΪ��λ
		double p=0.999;			//̽����
		int e=10;				//�𻵵Ŀ�����ʵ�����ǲ���Ԥ֪�ģ�	
		Stopwatch start=new  Stopwatch();	//��ʱ��
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		MHTPADD_02 mhtPDP=new MHTPADD_02(false,"pairing/e/e.properties");	
		//MHTPADD mhtPDP=new MHTPADD(false,"pairing/d/d_159.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//��ʼ����
		StdOut.println("-------------��ʼ����������------------");
		mhtPDP.setup();


		//���ļ�����Ԥ����
		StdOut.println("\n-------------���ļ�Ԥ����------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, mhtPDP.getPairing().getZr());
		Element[][] sectors=HDFSFileOperation.sectors;
		Element[] gdata=mhtPDP.allGElement(pdata);
		int fileBlocks=fileOper.getBlocksOfFile(fileName, blockSize);
		c=Sampling.getSampleBlocks(fileBlocks, e,p);
		StdOut.println("����������"+c);
		StdOut.println("�ļ�Ԥ�����ʱ��"+start.elapsedTime()+"ms");

		//��Կ����
		Map<String,Element> keyMap=mhtPDP.keyGen();	        
		
		//�������ֵ
		Element[] us=mhtPDP.pusGen(s);		

		//Ԫ��������
		Element[] blockTags=new Element[fileBlocks];
		StdOut.println("\n-------------����ÿ��ı�ǩ------------");
		for(int i=0;i<fileBlocks;i++){				
			blockTags[i]=mhtPDP.metaGen(i,gdata[i],keyMap.get(MHTPADD_01.SECRETKEY),sectors[i],us);
			StdOut.println((i+1)+"���ǩ��"+new String(Hex.encode(blockTags[i].toBytes())));
		}		

		//����MHT������Root����ǩ��,ǩ������512*4=2048bit
		MerkleHashTree mht=new MerkleHashTree(gdata);
		byte[] Root=mht.createMHT();				
		Element sigHashRoot=mhtPDP.sigRoot(Root, keyMap.get(MHTPADD_01.SECRETKEY));
		StdOut.println("\n-------------������ϣ��������������ǩ��------------");
		StdOut.println("root��"+new String(Hex.encode(Root)));
		StdOut.println("sigRoot��"+new String(Hex.encode(sigHashRoot.toBytes())));

		StdOut.println("\n==============verifier==============\n");

		StdOut.println("\n-------------������ս��Ϣ------------");
		//������ս		
		Chal [] challenge=mhtPDP.challengeGen(c,fileBlocks);	
		
		StdOut.println("\n-------------������ս------------");

		StdOut.println("\n==============Cloud Service Provider==============\n");
		//������������ս��Ϣ�����֤�ݵ�Ԫ����
		int [] blockNumChall=new int[c];//���
		Element [] vi=new Element[c];//�����
		Element [][] mij=new Element[c][s];//�����ս��Ķ���Ϣ
		Element [] ti=new Element[c];//���ǩ	
		Element [] Hmi =new Element[c];
		for(int i=0;i<c;i++){
			blockNumChall[i]=challenge[i].num;
			vi[i]=challenge[i].random;
			ti[i]=blockTags[challenge[i].num-1];
			for(int j=0;j<s;j++)
				mij[i][j]=sectors[challenge[i].num-1][j];	//ʵ��������pdata������������		
			Hmi[i]=gdata[challenge[i].num-1];			
		}
		StdOut.println("-------------����֤��------------");

		//����������֤��		
		Map<String,Object>aai=mht.genChalAAI(blockNumChall);//���㸨�������ռ� 
		Map<String,Object>proof=mhtPDP.genProof(vi, mij, ti,s);			
		proof.put("AAI",aai);
		proof.put("Hmi",Hmi);//Hmi�е�ֵ˳���Ӧ����ս��ŵ�˳��
		proof.put("sigHashRoot",sigHashRoot);	
		StdOut.println(proof);



		StdOut.println("\n==============verifier==============\n");

		//У���߸��ݿ���Ϣ����Root
		byte[] newRoot=mht.getRootByAuxiliaryIndex(aai,blockNumChall);
		StdOut.println("-------------���㲢��֤Root------------");
		StdOut.println("newRoot��"+new String(Hex.encode(newRoot)));

		//���֤��
		StdOut.println("\n-------------��֤���ݿ�------------");
		boolean rTrue=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_02.PUBLICKEY),us,challenge, proof);
		boolean rFalse2=mhtPDP.proofVerify(Root, keyMap.get(MHTPADD_02.PUBLICKEY).twice(), us,challenge,proof);
		proof.put("sigHashRoot", sigHashRoot.twice());
		boolean rFalse1=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_02.PUBLICKEY), us,challenge,proof);


		//��֤���
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------֤����Ч����������------------");

		StdOut.println("�ܺ�ʱ��"+start.elapsedTime()+"ms");
	}

}
