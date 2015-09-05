package LyaOptimal;

import java.math.BigDecimal;

import tool.StdDraw;
import tool.StdOut;


public class TestLyapunovOptimal {

	public 	static final int N=10;	//服务器的个数	
	private static final int k=1;	//频率的系数
	private static final int α=3;	//频率的三次方
	//private static final int V=10;	//能量——延迟的控制参数
	private static final double e=0.125; //完成与到达的最大速率差，单位s
	private static final double	p=0.8;//时间槽内P概率到达
	private static final int T=100000;	//时间槽总个数
	
	private static final double b=0.5;	//时间槽，单位s
	
	//任务量的设置
	public static final double taskC=3.2*0.75;	//任务的计算量，taskC=AT*S
	public static double taskScale=3.2*0.25; //任务计算量的变化幅度
	public static final int  taskType=6;	//任务类型
    
	private static final double S=3.2;	//基准CPU频率，单位GHz
	private static final double AT=taskC/S;//基准的完成时间,单位s,dispacher估计的
	
	//服务器频率设置
	public static final double Smin=2.0; 	//服务器最小的CPU频率，GHZ
	public static final double scale=0.1;	//服务器CPU频率的变化幅度
	//public static final double  Smax=2.9;		//服务器最大的CPU频率GHZ

	//调度算法
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
			ly.setUp(k, α, V, p, b, N, taskType,Smin, scale,taskC,taskScale);
			E=ly.averageTimeEnergy(T,BLQE);			
			qtime=ly.averageTimeQueue(T);				
			//StdOut.println(V+"\t"+E+"\t"+qtime);
			//StdOut.println("E1:"+ly.allEnergyCostS1+",E:"+ly.allEnergyCost+", E2:"+ly.allEnergyCostSN);
			ly.printServerTask();
		}
		}


	
}
