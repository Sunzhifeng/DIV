package LyaOptimal;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import tool.StdOut;



public class LyapunovOptimal {
	private  double taskC;	//任务的计算量
	private  double taskScale; //任务计算量的变化幅度
	private  int  	taskType;	//任务类型
	public   int k;				//CPU频率系数
	public   int α;			//频率的密系数
	private  double V;			//能量的动态调整量
	//private  double e;			//服务与输入的最大差
	private  double p;		//时间槽内P概率到达	
//	private  double S;		//基准CPU频率
	private  double b;		//时间槽
	//private  double AT;			//以S为基准，在时间t内的一个到达的完成时间
	public  int N;			//服务器的个数		
	public  double Smin; 	//服务器最小的CPU频率
	public double scale;	//服务器CPU频率的变化幅度
	public double Smax;		//服务器最大的CPU频率
	private Server[] servers;	//系统中服务器
	private Task[] tasks;
	public   double allEnergyCost=0.0; //T时间内的总能量消耗
	public double   allEnergyCostS1=0.0;//所有任务都交给server1执行的能耗
	public double   allEnergyCostSN=0.0;//所有任务都交给serverN执行能耗
	public  double averageQueue=0.0;
	public static int arrivalCount=0;	
	private  int roundCounter=0;	
	public static int count=0;
	public void setUp(int k,int α,double V,double p,double b ,int N,int taskType,double Smin,double scale,double taskC,double taskScale){
		this.k=k;
		this.α=α;
		this.V=V;		
		this.p=p;
		this.b=b;		
		this.N=N;
		this.Smin=Smin;
		this.scale=scale;
		this.taskC=taskC;
		this.taskScale=taskScale;
		servers=new Server[N+1];
		for(int i=1;i<=N;i++ ){
			servers[i]=new Server(i,Smin+scale*i,Server.Q0,Server.TASKBUFF,Server.IDLE);
		}
		tasks=new Task[taskType];
		for (int j=0;j<taskType;j++){
			tasks[j]=new Task(j+1,taskC+j*taskScale,0);
		}
	}
	//Request调度选择服务器
	public int 	BLQESelect(int t,int taskId,double v){//不同的t槽，server的状态不同
		int ut=0;//服务器编号
		double min=0.0;		
		min=getAiT(t,1,taskId)*servers[1].queueTime*2+energyCostI(t,1,taskId)*v/2;
		ut=1;
		for(int i=2;i<=N;i++){
			double temp=getAiT(t,i,taskId)*servers[i].queueTime*2+energyCostI(t,i,taskId)*v/2;//根据队列和能耗选择服务器
			if(min>temp){
				min=temp;
				ut=i;
			}
		}			
		return ut;

	}
	
	public int 	BLQESelect2(int t,int taskId,double v,int a){//不同的t槽，server的状态不同
		int ut=0;//服务器编号
		double min=0.0;		
		min=getAiT(t,1,taskId)*servers[1].queueTime*2+energyCostI(t,1,taskId)*v/a;
		ut=1;
		for(int i=2;i<=N;i++){
			double temp=getAiT(t,i,taskId)*servers[i].queueTime*2+energyCostI(t,i,taskId)*v/a;//根据队列和能耗选择服务器
			if(min>temp){
				min=temp;
				ut=i;
			}
		}			
		return ut;

	}
	//Random 选择服务器_以概率pi=si/(s1+s2+...+sN)
	public int  randomSelect(int t,int taskId){
		double  sumS=0;
		for (int i=1;i<=N;i++){
			sumS=sumS+servers[i].s;
		}
		double  rand=new Random().nextDouble();
		double temp=0;
		for(int j=1;j<=N;j++){
			temp=temp+servers[j].s;
			if(rand*sumS<=temp){//以服务器的CPU速度为比例进行分配
				return j;
			}
		}
		return 0;
	}

	//循环轮转调度
	public int roundRobin(int t,int taskId){
		return (roundCounter++)%N +1;
	}

	/*public double energyCost(int t,int taskId){//t时间槽内只有一个到达，且由i完成
		double result=0.0;
		for(int i=1;i<=N;i++){
			result=result+energyCostI(t,i);
		}
		return result;
	}*/


	//在t槽内到达，由i完成所花费的能量
	public double energyCostI(int t,int serverId,int taskId){		
		double ait=getAiT(t, serverId,taskId);
		return ait*k*Math.pow((double)(servers[serverId].s), α);
	}
    
	public double energyCostB(int t,int serverId){
		if(servers[serverId].state==Server.COMPUTING){
			return b*k*Math.pow((servers[serverId].s), α);
		}
		return 0.0;
	}
	
	/**
	 * 在第t个时间间隔开始时是否有新的到达——随机有很多的不缺定性，采用T*0.8
	 * @param t
	 * @return 任务类型编号
	 */
	public int isNewTaskArrival(int t){	//其实时第t-1个时间槽内的到达
		
		if(t==0){//初始时刻没有到达
			return 0;
		}
	/*	double p1= ran.nextDouble();//模仿时间间隔到达的伯努力分布		
		if(p1<p){//偶数，有到达		
			return 2;
		}*/
		this.arrivalCount++;
		if(arrivalCount%5==0)
		return 0;//0：表示无到达
		//return 6;
		//return (count++)%6+1;
		return new Random().nextInt(6)+1;
		
	}
	/**
	 * 第t个时槽到达的任务交由第i个server，所需要的计算时间
	 * @param t
	 * @param serverId 
	 * @param taskId  //任务的类型编号1-6
	 * @return 
	 */
	public double getAiT(int t,int serverId,int taskId){
		if(t==0||taskId==0){//初始状态，没有到达
			return  0.0;
		}
		return (tasks[taskId-1].c)/servers[serverId].s;//我们先假设任务量是相等的

	}

	//由时槽t，估计t+1时槽，第i个server的剩余队列时间
	public double getNextQi(int t ,int serverId,int taskId,int l){
		
		if(t==0){
			return servers[serverId].Q0;
		}
		double q=servers[serverId].queueTime-b;
		q=q>0?q:0;		
		return q+getAiT(t,serverId,taskId)*l;

	}

	
	/**
	 * 指定时间周期内的单位时间能耗
	 * @param T		时间周期
	 * @param schedul 选择的调度方法
	 * @return 
	 */
	public double averageTimeEnergy(int T,int schedul){
		double E=0.0;
		double E1=0.0;//所有任务都交给server1执行的能耗
		double EN=0.0;//所有任务都交给serverN执行的能耗
		double queueLength=0.0;
		for(int t=0;t<T;t++){
			int serverId=0; //为任务选择的服务器Id
			int arrival=this.isNewTaskArrival(t);//到达的任务类型
			
			if(arrival!=0){//时间槽开始时刻
				if(schedul==1){
					serverId=this.BLQESelect(t, arrival,V);
				}else if(schedul==2){
					serverId=randomSelect(t,arrival);
				}else if(schedul==3){
					serverId=this.roundRobin(t, arrival);
				}
				servers[serverId].task++;
				servers[serverId].state=Server.COMPUTING;
				//E=E+this.energyCostI(t, serverId,arrival);//估计能量消耗
				E1=E1+this.energyCostI(t,1,arrival);
				EN=EN+this.energyCostI(t, N,arrival);
			}
			
			for(int k=1;k<=N;k++){
				queueLength+=servers[k].queueTime;
				E=E+this.energyCostB(t, k);
			}
			//时间槽末尾，更新队列信息
			for(int j=1;j<=N;j++){
				if(j==serverId){//对于分配到任务的服务器特殊处理
					servers[j].queueTime=getNextQi(t, j,arrival,1);
				}else{
					servers[j].queueTime=getNextQi(t,j,arrival,0);
					if(servers[j].queueTime==0){//更新服务器状态
						servers[j].state=Server.IDLE;
					}
				}

			}


		}
		allEnergyCost=E;	
		allEnergyCostS1=E1;
		allEnergyCostSN=EN;
		averageQueue=queueLength/T;
		//StdOut.println(T*b+"s内的总能耗："+"E1="+E1+", E="+E+", EN="+EN);
		
		return E/T;

	}


	public double averageTimeQueue(int T){	
		//StdOut.println(e);
		return averageQueue;

	}

	public void printServerTask(){
		int sum=0;
		for(int i=1;i<=N;i++){
			sum+=servers[i].task;
			//StdOut.println("server"+i+":\t"+servers[i].task);
			StdOut.println(i+":\t"+servers[i].task);
		}
		StdOut.println("AllTask：\t"+sum);
	}
	
	
	//Lyapunov函数L(Q(t))= 1/2(Q1(t)^2+...+QN(t)^2)
	public double LyapunovFunction(int t){
		double temp=0.0;
		for(int i=1;i<=N;i++){
			temp=temp+servers[i].queueTime*servers[i].queueTime;
		}
		return temp/2;
	}

	//一个时槽内队列的方差
	public double diffLyapunovFunction(int t){
		double temp1=0.0;
		for(int i=1;i<=N;i++){
			double q=servers[i].queueTime;
			temp1=temp1+q*q;
		}
		return temp1/2-LyapunovFunction(t);
	}

	public double LyapunovDrift(){
		return 0.0;
	}

	/*public double getB(){//
	double minS=servers[1].s;
	for(int i=2;i<=N;i++){
		if(minS>servers[i].s)
			minS=servers[i].s;
	}
	double Amax=AT*S/minS;
	return (Amax*Amax+N*b*b)/2;
}*/


}
