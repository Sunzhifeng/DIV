package IHT;


import static org.junit.Assert.assertTrue;
import fileOperation.FileOperation;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.util.List;
import java.util.Map;

import tool.Accumulator;
import tool.DataFilter;
import tool.PropertiesUtil;
import tool.Sampling;
import tool.StdOut;
import tool.Stopwatch;
import IHT.IHTPADD_02.Chal;
import IHT.IndexHashTable.Item;

/**
 * IHTPADD_02���в���
 * @author MichaelSun
 * @version 1.0
 * @date 2014.12.22
 */
public class TestIHTPADD_02 {

	public static void main (String [] args) throws Exception{
		String filePath="d:/test/test-2.txt";		
		int c;					//��ս�Ŀ�����
		int s;					//ÿ��Ķ���
		int sectorSize=20;		//160bit		
		double p=0.999;			//̽����
		int e=10;				//�𻵵Ŀ�����ʵ�����ǲ���Ԥ֪�ģ�
		int []sampleC={20,40,60,80,100,120,140,160,180,200};
		int [] sPerBlock={50,100,150,200,250,300,350,400,450,500};
		for(int samp=0;samp<10;samp++){
			c=sampleC[samp];
			StdOut.println(c);
			for(int count=0;count<10;count++){
				Accumulator averDoTime=new Accumulator();
				Accumulator averIHTTime=new Accumulator();
				Accumulator averCSPTime=new Accumulator();
				Accumulator averVerTime=new Accumulator();
				Accumulator averTotal=new Accumulator();
				for(int avergaeTime=0;avergaeTime<10;avergaeTime++){				
					s=sPerBlock[count];				
					int blockSize=s*sectorSize/1000;//��kΪ��λ
					IHTPADD_02 ihtPADP=new IHTPADD_02(false,"pairing/d/d_159.properties");

					//��ʼ����
					ihtPADP.setup();


					//���ļ�����Ԥ����
					Map<String,Object> preData=FileOperation.preProcessFile(filePath, blockSize,s,sectorSize, ihtPADP.getPairing().getZr());
					Element[] pdata=(Element[])preData.get("pdata");
					List<Element[]> nSectors=(List<Element[]>)preData.get("nSectors");		
					int fileBlocks=FileOperation.blockNumbersOfFile(filePath, blockSize);
					//c=Sampling.getSampleBlocks(fileBlocks,e,p);
					//StdOut.println(c);
					//���������
					Element[]ps=ihtPADP.psGen(s);
					Element[] us=ihtPADP.usGen(ps);

					//�����û���Կ����ϣ��Կ
					Map<String,Element> keyMap=ihtPADP.keyGen();    
					Element hashKey =ihtPADP.getPairing().getZr().newZeroElement();
					hashKey=ihtPADP.hashKeyGen(ps,keyMap.get(IHTPADD_02.SECRETKEY));

					//����������ϣ��IHT
					double DoTime=0.00;
					double ihtTime=0.00;
					Stopwatch IHTTime=new  Stopwatch();	//��ʱ��	
					IndexHashTable ihtable=new IndexHashTable(filePath,fileBlocks);
					Item [] item=ihtable.createIHT2(ihtPADP.getPairing().getZr(),hashKey, ihtPADP.getPairing().getG1(),pdata);		
					Element[] Hid=ihtable.getHids();
					ihtTime+=IHTTime.elapsedTime();

					//�洢��ϣ��
					//FileOperation.saveItemArray(FileOperation.IHT, item);

					//Ԫ��������
					Element[] blockTags=new Element[fileBlocks];		
					Stopwatch genTagTime=new  Stopwatch();	//��ʱ��
					for(int i=0;i<fileBlocks;i++){				
						blockTags[i]=ihtPADP.metaGen(i,Hid[i+1],keyMap.get(IHTPADD_02.SECRETKEY),nSectors.get(i),ps);
					}	

					DoTime+=genTagTime.elapsedTime();
					DoTime=DataFilter.roundDouble(DoTime/1000, 3);	

					//�����ǩ���浽�ļ�
					//FileOperation.saveElementArray(FileOperation.BLOCKTAG, blockTags);

					//����DO��˽����Ϣ
					//FileOperation.saveMap(FileOperation.DO, IHTPADD_02.doPrivate);

					//���湫����Ϣ
					//FileOperation.saveMap(FileOperation.PUBLICINFOR,IHTPADD_02.publicInfor);


					//������ս��Ϣ��������Ϳ��ż���ս��ʶ
					Element r=ihtPADP.rGen();
					Map<String,Object> challengeR=ihtPADP.challengeGen(c,fileBlocks,keyMap.get(ihtPADP.PUBLICKEY),r,filePath);

					double CSPTime=0.00;
					double VerTime=0.00;			

					//������������ս��Ϣ�����֤�ݵ�Ԫ����	
					Chal[]challenge=(Chal[])challengeR.get("challenge");
					Element R=(Element)challengeR.get("R");
					int [] blockNumChall=new int[c];	//���
					Element [] vi=new Element[c];		//�����
					Element [][] mij=new Element[c][s]; //�����ս��Ķ���Ϣ
					Element [] ti=new Element[c];		//���ǩ	
					Item [] id =new Item[c]; 			//��ս���IHT�еı���
					Stopwatch genProofTime=new  Stopwatch();	//��ʱ��	
					for(int i=0;i<c;i++){
						blockNumChall[i]=challenge[i].num;
						vi[i]=challenge[i].random;
						ti[i]=blockTags[challenge[i].num-1];
						for(int j=0;j<s;j++)
							mij[i][j]=nSectors.get(challenge[i].num-1)[j];	//ʵ��������pdata������������		
						id[i]=item[challenge[i].num];			
					}


					//����������֤��		
					Map<String,Object>proof=ihtPADP.genProof3(vi, mij, ti,R,us);
					proof.put("id",id);		//������ս���ID					
					CSPTime+=genProofTime.elapsedTime();		

					//���֤��
					Stopwatch verproofTime=new  Stopwatch();	//��ʱ��
					boolean rTrue=ihtPADP.proofVerify( keyMap.get(ihtPADP.PUBLICKEY),r,challengeR,proof,filePath);
					//boolean rFalse1=ihtPADP.proofVerify( keyMap.get(ihtPADP.PUBLICKEY).twice(),r,challengeR,proof,fileName);
					//id[c-1]=item[1];//�������ݲ���
					//proof.put("id", id);
					//boolean rFalse2=ihtPADP.proofVerify( keyMap.get(ihtPADP.PUBLICKEY),r,challengeR,proof,fileName);
					VerTime+=verproofTime.elapsedTime();

					CSPTime=DataFilter.roundDouble(CSPTime/1000,3);				
					VerTime=DataFilter.roundDouble(VerTime/1000, 3);
					double total=DataFilter.roundDouble(DoTime+CSPTime+VerTime,3);

					averDoTime.addDataValue(DoTime);
					averIHTTime.addDataValue(ihtTime/1000);
					averCSPTime.addDataValue(CSPTime);
					averVerTime.addDataValue(VerTime);
					averTotal.addDataValue(total);
					//У���߱�����Ϣ
					//FileOperation.saveMap(FileOperation.Ver, IHTPADD_02.verInfor);

					//CSP������Ϣ
					//	FileOperation.saveMap(FileOperation.CSP, IHTPADD_02.cspInfor);

					//��֤���
					assertTrue(rTrue);
					//assertFalse(rFalse1);
					//assertFalse(rFalse2);
					//	StdOut.println(s+"\t"+DoTime+"\t"+CSPTime+"\t"+VerTime+"\t"+total);

				}
				StdOut.println(sPerBlock[count]+"\t"+DataFilter.roundDouble(averDoTime.mean(),3)+"\t"+
								DataFilter.roundDouble(averIHTTime.mean(),3)+"\t"
								+DataFilter.roundDouble(averCSPTime.mean(),3)+"\t"
								+DataFilter.roundDouble(averVerTime.mean(),3)+"\t"
								+DataFilter.roundDouble(averTotal.mean(),3));

			}
			
		}
	}
}
