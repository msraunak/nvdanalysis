
/**
 * Common Weakness Enumeration (CWE) Data Unit
 * @author msr4
 */
public class CWE {

	private int id;
	private String name;
	private int numOfVuln; // number of vulnerabilities under this category
	private boolean isNineteen; // is this CWE part of the 19 used by 
	
	public CWE (int cweId, String cweName){
		assert(cweId > 0 && cweId <100);
		this.id = cweId;
		this.name = cweName;
	}
	
	public int getId(){
		return id;
	}
	
	public String getName(){
		return name;
	}
}
