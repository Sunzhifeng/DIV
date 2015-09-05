package LyaOptimal;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import tool.StdOut;



public class LyapunovOptimal {
	private  double taskC;	//����ļ�����
	private  double taskScale; //����������ı仯����
	private  int  	taskType;	//��������
	public   int k;				//CPUƵ��ϵ��
	public   int ��;			//Ƶ�ʵ���ϵ��
	private  double V;			//�����Ķ�̬������
	//private  double e;			//���������������
	private  double p;		//ʱ�����P���ʵ���	
//	private  double S;		//��׼CPUƵ��
	private  double b;		//ʱ���
	//private  double AT;			//��SΪ��׼����ʱ��t�ڵ�һ����������ʱ��
	public  int N;			//�������ĸ���		
	public  double Smin; 	//��������С��CPUƵ��
	public double scale;	//������CPUƵ�ʵı仯����
	public double Smax;		//����������CPUƵ��
	private Server[] servers;	//ϵͳ�з�����
	private Task[] tasks;
	public   double allEnergyCost=0.0; //Tʱ���ڵ�����������
	public double   allEnergyCostS1=0.0;//�������񶼽���server1ִ�е��ܺ�
	public double   allEnergyCostSN=0.0;//�������񶼽���serverNִ���ܺ�
	public  double averageQueue=0.0;
	public static int arrivalCount=0;	
	private  int roundCounter=0;	
	public static int count=0;
	public void setUp(int k,int ��,double V,double p,double b ,int N,int taskType,double Smin,double scale,double taskC,double taskScale){
		this.k=k;
		this.��=��;
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
	//Request����ѡ�������
	public int 	BLQESelect(int t,int taskId,double v){//��ͬ��t�ۣ�server��״̬��ͬ
		int ut=0;//���������
		double min=0.0;		
		min=getAiT(t,1,taskId)*servers[1].queueTime*2+energyCostI(t,1,taskId)*v/2;
		ut=1;
		for(int i=2;i<=N;i++){
			double temp=getAiT(t,i,taskId)*servers[i].queueTime*2+energyCostI(t,i,taskId)*v/2;//���ݶ��к��ܺ�ѡ�������
			if(min>temp){
				min=temp;
				ut=i;
			}
		}			
		return ut;

	}
	
	public int 	BLQESelect2(int t,int taskId,double v,int a){//��ͬ��t�ۣ�server��״̬��ͬ
		int ut=0;//���������
		double min=0.0;		
		min=getAiT(t,1,taskId)*servers[1].queueTime*2+energyCostI(t,1,taskId)*v/a;
		ut=1;
		for(int i=2;i<=N;i++){
			double temp=getAiT(t,i,taskId)*servers[i].queueTime*2+energyCostI(t,i,taskId)*v/a;//���ݶ��к��ܺ�ѡ�������
			if(min>temp){
				min=temp;
				ut=i;
			}
		}			
		return ut;

	}
	//Random ѡ�������_�Ը���pi=si/(s1+s2+...+sN)
	public int  randomSelect(int t,int taskId){
		double  sumS=0;
		for (int i=1;i<=N;i++){
			sumS=sumS+servers[i].s;
		}
		double  rand=new Random().nextDouble();
		double temp=0;
		for(int j=1;j<=N;j++){
			temp=temp+servers[j].s;
			if(rand*sumS<=temp){//�Է�������CPU�ٶ�Ϊ�������з���
				return j;
			}
		}
		return 0;
	}

	//ѭ����ת����
	public int roundRobin(int t,int taskId){
		return (roundCounter++)%N +1;
	}

	/*public double energyCost(int t,int taskId){//tʱ�����ֻ��һ���������i���
		double result=0.0;
		for(int i=1;i<=N;i++){
			result=result+energyCostI(t,i);
		}
		return result;
	}*/


	//��t���ڵ����i��������ѵ�����
	public double energyCostI(int t,int serverId,int taskId){		
		double ait=getAiT(t, serverId,taskId);
		return ait*k*Math.pow((double)(servers[serverId].s), ��);
	}
    
	public double energyCostB(int t,int serverId){
		if(servers[serverId].state==Server.COMPUTING){
			return b*k*Math.pow((servers[serverId].s), ��);
		}
		return 0.0;
	}
	
	/**
	 * �ڵ�t��ʱ������ʼʱ�Ƿ����µĵ��������кܶ�Ĳ�ȱ���ԣ�����T*0.8
	 * @param t
	 * @return �������ͱ��
	 */
	public int isNewTaskArrival(int t){	//��ʵʱ��t-1��ʱ����ڵĵ���
		
		if(t==0){//��ʼʱ��û�е���
			return 0;
		}
	/*	double p1= ran.nextDouble();//ģ��ʱ��������Ĳ�Ŭ���ֲ�		
		if(p1<p){//ż�����е���		
			return 2;
		}*/
		this.arrivalCount++;
		if(arrivalCount%5==0)
		return 0;//0����ʾ�޵���
		//return 6;
		//return (count++)%6+1;
		return new Random().nextInt(6)+1;
		
	}
	/**
	 * ��t��ʱ�۵���������ɵ�i��server������Ҫ�ļ���ʱ��
	 * @param t
	 * @param serverId 
	 * @param taskId  //��������ͱ��1-6
	 * @return 
	 */
	public double getAiT(int t,int serverId,int taskId){
		if(t==0||taskId==0){//��ʼ״̬��û�е���
			return  0.0;
		}
		return (tasks[taskId-1].c)/servers[serverId].s;//�����ȼ�������������ȵ�

	}

	//��ʱ��t������t+1ʱ�ۣ���i��server��ʣ�����ʱ��
	public double getNextQi(int t ,int serverId,int taskId,int l){
		
		if(t==0){
			return servers[serverId].Q0;
		}
		double q=servers[serverId].queueTime-b;
		q=q>0?q:0;		
		return q+getAiT(t,serverId,taskId)*l;

	}

	
	/**
	 * ָ��ʱ�������ڵĵ�λʱ���ܺ�
	 * @param T		ʱ������
	 * @param schedul ѡ��ĵ��ȷ���
	 * @return 
	 */
	public double averageTimeEnergy(int T,int schedul){
		double E=0.0;
		double E1=0.0;//�������񶼽���server1ִ�е��ܺ�
		double EN=0.0;//�������񶼽���serverNִ�е��ܺ�
		double queueLength=0.0;
		for(int t=0;t<T;t++){
			int serverId=0; //Ϊ����ѡ��ķ�����Id
			int arrival=this.isNewTaskArrival(t);//�������������
			
			if(arrival!=0){//ʱ��ۿ�ʼʱ��
				if(schedul==1){
					serverId=this.BLQESelect(t, arrival,V);
				}else if(schedul==2){
					serverId=randomSelect(t,arrival);
				}else if(schedul==3){
					serverId=this.roundRobin(t, arrival);
				}
				servers[serverId].task++;
				servers[serverId].state=Server.COMPUTING;
				//E=E+this.energyCostI(t, serverId,arrival);//������������
				E1=E1+this.energyCostI(t,1,arrival);
				EN=EN+this.energyCostI(t, N,arrival);
			}
			
			for(int k=1;k<=N;k++){
				queueLength+=servers[k].queueTime;
				E=E+this.energyCostB(t, k);
			}
			//ʱ���ĩβ�����¶�����Ϣ
			for(int j=1;j<=N;j++){
				if(j==serverId){//���ڷ��䵽����ķ��������⴦��
					servers[j].queueTime=getNextQi(t, j,arrival,1);
				}else{
					servers[j].queueTime=getNextQi(t,j,arrival,0);
					if(servers[j].queueTime==0){//���·�����״̬
						servers[j].state=Server.IDLE;
					}
				}

			}


		}
		allEnergyCost=E;	
		allEnergyCostS1=E1;
		allEnergyCostSN=EN;
		averageQueue=queueLength/T;
		//StdOut.println(T*b+"s�ڵ����ܺģ�"+"E1="+E1+", E="+E+", EN="+EN);
		
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
		StdOut.println("AllTask��\t"+sum);
	}
	
	
	//Lyapunov����L(Q(t))= 1/2(Q1(t)^2+...+QN(t)^2)
	public double LyapunovFunction(int t){
		double temp=0.0;
		for(int i=1;i<=N;i++){
			temp=temp+servers[i].queueTime*servers[i].queueTime;
		}
		return temp/2;
	}

	//һ��ʱ���ڶ��еķ���
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
