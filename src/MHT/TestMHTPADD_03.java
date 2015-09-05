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
import MHT.MHTPADD_03.Chal;


/**
 * MHTPADD_03���в���
 * @author MichaelSun
 * @version 3.0
 * @date 2014.12.16
 */
public class TestMHTPADD_03 {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";	
		int c=30;					//��ս�Ŀ�����
		int s;				//ÿ��Ķ���
		int sectorSize=20;		//160bit	
		double p=0.999;			//̽����
		int e=10;				//�𻵵Ŀ�����ʵ�����ǲ���Ԥ֪�ģ�
		//int []sampleC={20,40,60,80,100,120,140,160};
		int [] sPerBlock={100,200,300,400,500,600,700,800,900,1000};		
		for(int count=0;count<sPerBlock.length;count++){
			//StdOut.println("count:"+(count+1));
			s=sPerBlock[count];
			//c=sampleC[count];			
			StdOut.print(s+"\t");
			int blockSize=s*sectorSize/1000;//��kΪ��λ
			//Stopwatch start=new  Stopwatch();	//��ʱ��
			HDFSFileOperation fileOper=new HDFSFileOperation();		
			MHTPADD_03 mhtPDP=new MHTPADD_03(false,"pairing/d/d_159.properties");	

			//StdOut.println("\n==============DataOwner==============\n");

			//��ʼ����
			//StdOut.println("-------------��ʼ����������------------");
			mhtPDP.setup();


			//���ļ�����Ԥ����
			//StdOut.println("\n-------------���ļ�Ԥ����------------");
			Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, mhtPDP.getPairing().getZr());
			Element[][] sectors=HDFSFileOperation.sectors;
			Element[] gdata=mhtPDP.allGElement(pdata);
			int fileBlocks=fileOper.getBlocksOfFile(fileName, blockSize);
			//c=Sampling.getSampleBlocks(fileBlocks,e,p);
		//	StdOut.print(fileBlocks+"\t");	
			//	StdOut.println("����������"+c);
			//StdOut.println("�ļ�Ԥ�����ʱ��"+start.elapsedTime()+"ms");

			//��Կ����
		//	StdOut.println("\n-------------������Կ------------");
			Map<String,Element> keyMap=mhtPDP.keyGen();    

			//���������
			Element[]ps=mhtPDP.psGen(s);
			Element[] us=mhtPDP.usGen(ps);	

			//Ԫ��������		
		//	StdOut.println("\n-------------����ÿ��ı�ǩ------------");
			Stopwatch DOTime=new  Stopwatch();	//��ʱ��
			Stopwatch taggenTime=new  Stopwatch();	//��ʱ��
			Element[] blockTags=new Element[fileBlocks];	
			for(int i=0;i<fileBlocks;i++){				
				blockTags[i]=mhtPDP.metaGen(i,gdata[i],keyMap.get(MHTPADD_03.SECRETKEY),sectors[i],ps);
			}		
			StdOut.print(taggenTime.elapsedTime()/1000+"\t");
			//����MHT������Root����ǩ��,ǩ������512*4=2048bit
			//StdOut.println("\n-------------������ϣ��������������ǩ��------------");
			//Stopwatch mhtTime=new  Stopwatch();	//��ʱ��
			MerkleHashTree mht=new MerkleHashTree(gdata);
			byte[] Root=mht.createMHT();				
			Element sigHashRoot=mhtPDP.sigRoot(Root, keyMap.get(MHTPADD_03.SECRETKEY));
			//StdOut.println("��ʱ��"+mhtTime.elapsedTime());
			double temp1=DOTime.elapsedTime()/1000;
			StdOut.print(temp1+"\t");

		//	StdOut.println("\n==============verifier==============\n");

			//������ս
			//StdOut.println("\n-------------������ս��Ϣ------------");
			Chal [] challenge=mhtPDP.challengeGen(c,fileBlocks);
			//StdOut.println("\n-------------������ս------------");

			//StdOut.println("\n==============Cloud Service Provider==============\n");
			//������������ս��Ϣ�����֤�ݵ�Ԫ����
			int [] blockNumChall=new int[c];//���
			Element [] vi=new Element[c];//�����
			Element [][] mij=new Element[c][s];//�����ս��Ķ���Ϣ
			Element [] ti=new Element[c];//���ǩ	
			Element [] Hmi =new Element[c];
			Stopwatch genProofTime=new  Stopwatch();	//��ʱ��
			for(int i=0;i<c;i++){
				blockNumChall[i]=challenge[i].num;
				vi[i]=challenge[i].random;
				ti[i]=blockTags[challenge[i].num-1];
				for(int j=0;j<s;j++)
					mij[i][j]=sectors[challenge[i].num-1][j];	//ʵ��������pdata������������		
				Hmi[i]=gdata[challenge[i].num-1];			
			}
			//StdOut.println("-------------���У��������Ϣ------------");

			//����������֤��	
			//StdOut.println("-------------����֤��------------");
			
			Map<String,Object>aai=mht.genChalAAI(blockNumChall);//���㸨�������ռ� 


			Map<String,Object>proof=mhtPDP.genProof(vi, mij, ti,s);		
			proof.put("AAI",aai);
			proof.put("Hmi",Hmi);//Hmi�е�ֵ˳���Ӧ����ս��ŵ�˳��
			proof.put("sigHashRoot",sigHashRoot);	
			//StdOut.println(proof);
			double temp2=genProofTime.elapsedTime()/1000;
			StdOut.print(temp2+"\t");


		//	StdOut.println("\n==============verifier==============\n");

			Stopwatch verProofTime=new  Stopwatch();	//��ʱ��
			//У���߸��ݿ���Ϣ����Root
		//	StdOut.println("-------------���㲢��֤Root------------");
			byte[] newRoot=mht.getRootByAuxiliaryIndex(aai,blockNumChall);

			//StdOut.println("\n-------------��֤���ݿ�------------");
			boolean rTrue=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_03.PUBLICKEY),us,challenge, proof);
		//	boolean rFalse2=mhtPDP.proofVerify(Root, keyMap.get(MHTPADD_03.PUBLICKEY).twice(), us,challenge,proof);
			//proof.put("sigHashRoot", sigHashRoot.twice());
			//boolean rFalse1=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_03.PUBLICKEY), us,challenge,proof);
			double temp3=verProofTime.elapsedTime()/1000;
			StdOut.print(temp3+"\t");
			StdOut.println((temp1+temp2+temp3)+"\t");

			//��֤���
			assertTrue(rTrue);
			//assertFalse(rFalse1);
			//assertFalse(rFalse2);
			//StdOut.println("\n-------------֤����Ч����������------------");

			//StdOut.println("�ܺ�ʱ��"+start.elapsedTime()+"ms");
		}
	

	}
}
