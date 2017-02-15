import java.util.HashMap;
import java.util.Map;

/**
 * Common Weakness Enumeration (CWE) Data Unit
 * @author msr4
 */
public class CWE {

	private String id;
	private String name;
	private int numOfVuln; // number of vulnerabilities under this category
	private int year; // the year for which this data is searched; 0 when year is not specified
	private boolean oneOfNIST19; // is this CWE part of the 19 used by
	private Map<Integer, Integer> vulnByYear;
	
	// Constructor
	public CWE (String cweId, String cweName){
		this.id = cweId;
		this.name = cweName;
		this.numOfVuln = 0;
		this.year = 0;
		this.oneOfNIST19 = CweList.isPartOfNist19(cweId);
		this.vulnByYear = new HashMap<Integer, Integer>();
	}

	
	public String getId(){
		return id;
	}
	
	public String getName(){
		return name;
	}
	
	public boolean isOneOfNIST19(){
		return oneOfNIST19;
	}
	
	/**
	 * Set the value of the number of vulnerabilities found under this CWE category
	 */
	public void setNumOfVuln(int num){
		if (num > 0){
			this.numOfVuln = num;
		}
	}
	/**
	 * Returns the string representation of this data
	 */
	public String toString(){
		String str = "CWE-"+ getId() + "  " + getName();
		if ( isOneOfNIST19() )
			str += "  NIST"; 
		else
			str += " NON_NIST";
		return str;
	}


}
