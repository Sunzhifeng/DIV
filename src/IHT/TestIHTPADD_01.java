package IHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.Sampling;
import tool.StdOut;
import tool.Stopwatch;
import IHT.IHTPADD_01.Chal;
import IHT.IndexHashTable.Item;



/**
 * IHTPADD_01���в���
 * @author MichaelSun
 * @version 1.0
 * @date 2014.12.22
 */
public class TestIHTPADD_01 {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";	
		int c;					//��ս�Ŀ�����
		int s=200;				//ÿ��Ķ���
		int sectorSize=20;		//160bit
		int blockSize=s*sectorSize/1000;//��kΪ��λ
		double p=0.999;			//̽����
		int e=10;				//�𻵵Ŀ�����ʵ�����ǲ���Ԥ֪�ģ�

		Stopwatch start=new  Stopwatch();	//��ʱ��
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		IHTPADD_01 ihtPADP=new IHTPADD_01(false,"pairing/d/d_159.properties");
		StdOut.println("\n==============DataOwner==============\n");

		//��ʼ����
		StdOut.println("-------------��ʼ����������------------");
		ihtPADP.setup();


		//���ļ�����Ԥ����
		StdOut.println("\n-------------���ļ�Ԥ����------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, ihtPADP.getPairing().getZr());
		StdOut.println("�ļ�Ԥ�����ʱ��"+start.elapsedTime()+"ms");
		Element[][] sectors=HDFSFileOperation.sectors;		
		int fileBlocks=fileOper.getBlocksOfFile(fileName, blockSize);
		c=Sampling.getSampleBlocks(fileBlocks, e,p);
		StdOut.println("����������"+c);

		//��Կ����
		Map<String,Element> keyMap=ihtPADP.keyGen();	        
		StdOut.println("\n-------------������Կ------------");

		//�������ps��us
		Element[] ps = ihtPADP.psGen(s);
		Element[] us = ihtPADP.usGen(ps);

		//����������ϣ��IHT
		IndexHashTable ihtable=new IndexHashTable(fileName,fileBlocks);			
		Item [] item=ihtable.createIHT(ihtPADP.getPairing().getZr(),keyMap.get(ihtPADP.SECRETKEY) , ihtPADP.getPairing().getG1());		
		//�õ��Ĺ�ϣ��
		Element[] Hid=ihtable.getHids();

		//Ԫ��������
		Element[] blockTags=new Element[fileBlocks];
		StdOut.println("\n-------------����ÿ��ı�ǩ------------");
		Stopwatch genTagTime=new  Stopwatch();	//��ʱ��
		for(int i=0;i<fileBlocks;i++){				
			blockTags[i]=ihtPADP.metaGen(i,Hid[i+1],keyMap.get(IHTPADD_01.SECRETKEY),sectors[i],ps);
			//StdOut.println((i+1)+"���ǩ��"+new String(Hex.encode(blockTags[i].toBytes())));
		}		
		StdOut.println("��ʱ��"+genTagTime.elapsedTime());


		StdOut.println("\n==============verifier==============\n");

		//������ս		
		
		Chal [] challenge=ihtPADP.challengeGen(c,fileBlocks,fileName);
		StdOut.println("\n-------------������ս��Ϣ------------");
		/*for(Chal chal:challenge){
			StdOut.println("(���ţ������): "+"("+chal.num+","+chal.random+")");
		}
		StdOut.println("\n-------------������ս------------");*/


		StdOut.println("\n==============Cloud Service Provider==============\n");
		//������������ս��Ϣ�����֤�ݵ�Ԫ����
		int [] blockNumChall=new int[c];	//���
		Element [] vi=new Element[c];		//�����
		Element [][] mij=new Element[c][s]; //�����ս��Ķ���Ϣ
		Element [] ti=new Element[c];		//���ǩ	
		Item [] ids =new Item[c]; 			//��ս���IHT�еı���
		for(int i=0;i<c;i++){
			blockNumChall[i]=challenge[i].num;
			vi[i]=challenge[i].random;
			ti[i]=blockTags[challenge[i].num-1];
			for(int j=0;j<s;j++)
				mij[i][j]=sectors[challenge[i].num-1][j];	//ʵ��������pdata������������		
			ids[i]=item[challenge[i].num];	

		}


		//����������֤��		
		StdOut.println("-------------����֤��------------");
		Stopwatch genProofTime=new  Stopwatch();	//��ʱ��			
		Map<String,Object>proof=ihtPADP.genProof(vi, mij, ti,us);	
		proof.put("id",ids);		//������ս���ID
		//StdOut.println(proof);
		StdOut.println("��ʱ��"+genProofTime.elapsedTime());

		
		StdOut.println("\n==============verifier==============\n");
		//���֤��
		StdOut.println("\n-------------��֤���ݿ�------------");
		Stopwatch verproofTime=new  Stopwatch();	//��ʱ��
		boolean rTrue=ihtPADP.proofVerify(challenge,keyMap.get(ihtPADP.PUBLICKEY),proof,us);
		boolean rFalse1=ihtPADP.proofVerify(challenge,keyMap.get(ihtPADP.PUBLICKEY).twice(),proof,us);
		ids[c-1]=item[1];//�������ݲ���
		proof.put("id", ids);
		boolean rFalse2=ihtPADP.proofVerify(challenge,keyMap.get(ihtPADP.PUBLICKEY),proof,us);
		StdOut.println("��ʱ��"+verproofTime.elapsedTime());

		//��֤���
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------֤����Ч����������------------");

		StdOut.println("�ܺ�ʱ��"+start.elapsedTime()+"ms");
	}

}
