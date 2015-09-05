package IHT;

import static org.junit.Assert.assertTrue;
import fileOperation.FileOperation;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import tool.DataFilter;
import tool.EnergyCost;
import tool.PropertiesUtil;
import tool.StdOut;
import tool.Stopwatch;
import FEPAD.TransferCost;
import IHT.IndexHashTable.Item;

/**
 * �̶������ֶ����ս����У���ʱ������
 * @author MichaelSun
 * @version 1.0
 * @date 2014.1.05
 */
public class TestIHTPADD_02_chal {		

	public static void main (String [] args) throws Exception{
		PropertiesUtil p=new PropertiesUtil();
		String fileName="d:/test/test-2.txt";	
		int  q=30;		//CSP�Ĵ����ٶ���У���ߵ�q��
		int  w=50;		//��λKB/s		
		int []challCounts={1,2,3,5,6,10,15,30};
		int c=30;					//��ս�Ŀ�����
		int s=400;					//ÿ��Ķ���
		int sectorSize=20;		//160bit			
		int [] samplec={47,135,130,172,4,79,247,6,199,204,238,181,65,246,158,
				67,22,114,136,85,170,145,11,94,200,14,229,106,102,179};

		//int [] eBlocks=GenerateRandom.random(1, samplec.length, 3); 
		int [] eBlocks={14,22,27};	
		
		for(int count=0;count<1;count++){						
			StdOut.println("s="+s+",\t"+"c="+c+",\tq="+q+",\tw="+w+"KB/s");
			int blockSize=s*sectorSize/1000;//��kΪ��λ			
			IHTPADD_02 ihtPADP=new IHTPADD_02(false,"pairing/d/d_159.properties");

			//��ʼ����
			ihtPADP.setup();

			//���ļ�����Ԥ����
			Map<String,Object> preData=FileOperation.preProcessFile(fileName, blockSize,s,sectorSize, ihtPADP.getPairing().getZr());
			Element[] pdata=(Element[])preData.get("pdata");
			List<Element[]> nSectors=(List<Element[]>)preData.get("nSectors");	
			int fileBlocks=FileOperation.blockNumbersOfFile(fileName, blockSize);

			//���������
			Element[] ps = ihtPADP.psGen(s);
			Element[] us = ihtPADP.usGen(ps);

			//��Կ����
			Map<String,Element> keyMap=ihtPADP.keyGen();    

			//����������ϣ��IHT
			double DoTime=0.00;
			Stopwatch IHTTime=new  Stopwatch();	//��ʱ��	
			IndexHashTable ihtable=new IndexHashTable(fileName,fileBlocks);			
			Item [] item=ihtable.createIHT2(ihtPADP.getPairing().getZr(),keyMap.get(ihtPADP.SECRETKEY) , ihtPADP.getPairing().getG1(),pdata);		
			Element[] Hid=ihtable.getHids();			
			DoTime+=IHTTime.elapsedTime();

			//Ԫ��������
			Element[] blockTags=new Element[fileBlocks];		
			Stopwatch genTagTime=new  Stopwatch();	//��ʱ��
			for(int i=0;i<fileBlocks;i++){				
				blockTags[i]=ihtPADP.metaGen(i,Hid[i+1],keyMap.get(IHTPADD_02.SECRETKEY),nSectors.get(i),ps);
			}	
			DoTime+=genTagTime.elapsedTime();	
			DoTime=DataFilter.roundDouble(DoTime/1000, 3);
			StdOut.println("dataOwner Time Cost(s): "+DoTime);
			double CSPTime=0.00;
			double VerTime=0.00;
			double transTime=0.00;
			double transCost=0.00;//kb
			//���Զ����ս
			int challCount=3;
			for(int n=0;n<challCounts.length;n++){
				challCount=challCounts[n];
				for(int m=0;m<challCount;m++){
					int cChal=c/challCount;//ÿ����ս�Ŀ���
					int startNum=1+m*cChal;//��һ��
					int endNum=startNum+cChal-1;
					//������ս�������ʶr
					Element r=ihtPADP.rGen();
					Map<String,Object> challengeKR=ihtPADP.challengeGen3(samplec,startNum,endNum,keyMap.get(IHTPADD_02.PUBLICKEY),r,fileName);

					//������������ս��Ϣ�����֤�ݵ�Ԫ����					
					int [] blockNumChall=(int[])challengeKR.get("blocknum");	//���
					Element R=(Element)challengeKR.get("R");	//������ս�������־		
					BigInteger k1=(BigInteger)challengeKR.get("k1");//�����������hash��Կ��				
					Element [][] mij=new Element[cChal][s]; //�����ս��Ķ���Ϣ
					Element [] ti=new Element[cChal];		//���ǩ	
					Item [] id =new Item[cChal]; 			//��ս���IHT�еı���
					Stopwatch genProofTime=new  Stopwatch();	//��ʱ��	
					Element [] vi=ihtPADP.randomVi(cChal, blockNumChall, k1, ihtPADP.getPairing().getZr());		//�����
					for(int i=0;i<cChal;i++){				
						ti[i]=blockTags[blockNumChall[i]-1];
						for(int j=0;j<s;j++)
							mij[i][j]=nSectors.get(blockNumChall[i]-1)[j];	//ʵ��������pdata������������		
						id[i]=item[blockNumChall[i]];			
					}

					//����������֤��		
					Map<String,Object>proof=ihtPADP.genProof4(vi, mij, ti,R,us);
					proof.put("id",id);		//������ս���ID
					CSPTime+=genProofTime.elapsedTime();				

					//���֤��
					Stopwatch verproofTime=new  Stopwatch();	//��ʱ��
					boolean rTrue=ihtPADP.proofVerify2( keyMap.get(IHTPADD_02.PUBLICKEY),r,challengeKR,proof,fileName);
					assertTrue(rTrue);	
					VerTime+=verproofTime.elapsedTime();
					transCost+=TransferCost.IHTPADDTransCost(cChal, 256, 20);
				}	

				CSPTime=DataFilter.roundDouble(CSPTime/(q*1000),3);				
				VerTime=DataFilter.roundDouble(VerTime/1000, 3);
				transCost=DataFilter.roundDouble(transCost, 3);
				transTime=DataFilter.roundDouble(transCost/w, 3);
				double total=DataFilter.roundDouble(CSPTime+VerTime+transTime,3);
				StdOut.println(challCount+"\t"+CSPTime+"\t"+VerTime+"\t"+transTime+"\t"+total);
				//StdOut.println(transCost+"KB");
			}

		}
	}
}
