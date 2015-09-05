package LyaOptimal;

import java.math.BigDecimal;

import tool.StdDraw;
import tool.StdOut;


public class TestLyapunovOptimal {

	public 	static final int N=10;	//�������ĸ���	
	private static final int k=1;	//Ƶ�ʵ�ϵ��
	private static final int ��=3;	//Ƶ�ʵ����η�
	//private static final int V=10;	//���������ӳٵĿ��Ʋ���
	private static final double e=0.125; //����뵽���������ʲ��λs
	private static final double	p=0.8;//ʱ�����P���ʵ���
	private static final int T=100000;	//ʱ����ܸ���
	
	private static final double b=0.5;	//ʱ��ۣ���λs
	
	//������������
	public static final double taskC=3.2*0.75;	//����ļ�������taskC=AT*S
	public static double taskScale=3.2*0.25; //����������ı仯����
	public static final int  taskType=6;	//��������
    
	private static final double S=3.2;	//��׼CPUƵ�ʣ���λGHz
	private static final double AT=taskC/S;//��׼�����ʱ��,��λs,dispacher���Ƶ�
	
	//������Ƶ������
	public static final double Smin=2.0; 	//��������С��CPUƵ�ʣ�GHZ
	public static final double scale=0.1;	//������CPUƵ�ʵı仯����
	//public static final double  Smax=2.9;		//����������CPUƵ��GHZ

	//�����㷨
	public static final int BLQE=1;
	public static final int RANDOM=2;
	public static final int ROUND=3;
	public static void main(String[] args){			

		//for(int i=0;i<=40;i++){			
			for(int V=1;V<=20;V++){
			//	int T=i*10000;
			
			//double V=(double)i*0.05;
			LyapunovOptimal ly=new LyapunovOptimal();		
			double E=0.0;
			double qtime=0.0;
			ly.setUp(k, ��, V, p, b, N, taskType,Smin, scale,taskC,taskScale);
			E=ly.averageTimeEnergy(T,BLQE);			
			qtime=ly.averageTimeQueue(T);				
			//StdOut.println(V+"\t"+E+"\t"+qtime);
			//StdOut.println("E1:"+ly.allEnergyCostS1+",E:"+ly.allEnergyCost+", E2:"+ly.allEnergyCostSN);
			ly.printServerTask();
		}
		}


	
}
