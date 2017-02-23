import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.HashSet;


/**
 * Common Weakness Enumeration (CWE) Data Unit
 * @author msr4
 */
public class CWE implements Comparable <CWE> {
	
	private String id;
	private String name;
	private String type; // "C":Config, "I":Implementation, "D":Design, "U":Uncategorized
	private boolean oneOfNIST19; // is this CWE part of the 19 used by NIST
	private int numOfVulnTotal; // number of vulnerabilities under this category
	private Map<Integer, Integer> vulnByYear;
	
	// Constructor
	public CWE (String cweId, String cweName){
		this.id = cweId;
		this.name = cweName;
		CWE.setType(this); 
		// this.oneOfNIST19 = isPartOfNist19(cweId);
		this.numOfVulnTotal = 0;
		this.vulnByYear = new TreeMap<Integer, Integer>();
	}

	
	public String getId(){
		return this.id;
	}
	public String getName(){
		return this.name;
	}
	public String getType(){
		return this.type;
	}
	public void setType(String typeToSet){
		this.type = typeToSet;
	}
	public boolean isOneOfNIST19(){
		return this.oneOfNIST19;
	}
	public void setOneOfNIST19(boolean yesNo){
		this.oneOfNIST19 = yesNo;
	}
	public int getNumOfVulnTotal(){
		return this.numOfVulnTotal;
	}
	public Map<Integer,Integer> getVulnByYear(){
		return this.vulnByYear;
	}
	
	/**
	 * Set the value of the number of vulnerabilities found under this CWE category
	 */
	public void setNumOfVuln(int num){
		if (num > 0){
			this.numOfVulnTotal = num;
		}
	}
	// number of vulnerabilities in a year
	public void addNumVulnInYear(int year, int numOfVuln){
		assert(year>1992 && year<2017);
		vulnByYear.put(year, numOfVuln);
	}
	
	/**
	 * Returns the string representation of this data
	 */
	public String toString(){
		String str = "CWE-"+ getId() + "  " + getName() + "  " + getType();
		if ( isOneOfNIST19() )
			str += " NIST19"; 
		else
			str += " Non_Nist19";
		str += "\t\t";
				
		for( Integer year: vulnByYear.keySet()){
			str += "\t" + vulnByYear.get(year);
		}

		return str;
	}

	// Print the number of vulnerabilities by year
	public void printVulnByYear(){
		String str = "CWE-"+ getId() + "  " + getName();
		for( Integer year: vulnByYear.keySet() ){
			System.out.println("CWE-" + getId() + " " + year + " : " + vulnByYear.get(year));
		}
		System.out.println();
		
		
	}

	// static codes
	public static final int[] nist19={16,20,22,59,78,
			79,89,94,119,134,
			189,200,255,264,287,
			310,352,362,399};

	// The types are C: Config, I:Implementation, D:Design
	public static final String[] nist19Types={"C","I","I","I","I",
									"I","I","I","I","I",
									"I","C","D","D","D",
									"D","I","I","I"};

	// A set of nist19 entries
	private static Set<Integer> nistSet;
 
	// Create a set of the NIST used CWE IDs
	static {
		nistSet = new HashSet<Integer>();
		for (int i=0; i<nist19.length; i++){
			nistSet.add(new Integer(nist19[i]));
		}
	}
	
	/**
	 * Get the index of the nist19 entry in the static array nist19
	 * @param nist19Entry the cweId of the NIST19
	 * @return the index in the array
	 */
	public static int getIndex(int nist19Entry){
		
		for (int i=0; i<nist19.length;i++){
			if (nist19[i]==nist19Entry)
				return i;			
		}
		throw new IllegalArgumentException(); // if nist19Entry was actually NOT one of the NIST19
	}
	
	/**
	 * Check if a particular CWE_ID is one of the 19 used by NIST 
	 * @param cweId The id of the Common Weakness Enumeration
	 * @return
	 */
	public static void setType(CWE objCwe){
		Integer id;
		try {
			id = Integer.parseInt(objCwe.getId());
			if ( nistSet.contains(id) ){ 
				objCwe.setOneOfNIST19(true);
				objCwe.setType(nist19Types[getIndex(id)]);
			} else {
				objCwe.setOneOfNIST19(false);
				objCwe.setType("U");
			}
		} catch (NumberFormatException nfe) { // it's either CWE-Other or CWE-noinfo
			objCwe.setOneOfNIST19(false);
			objCwe.setType("U");
		}
	}


	@Override
	public int compareTo(CWE otherCWE) {

		int thisId, otherId;
		try {
			thisId = Integer.parseInt(this.getId());
			otherId = Integer.parseInt(otherCWE.getId());
			return (thisId - otherId);
		} catch (NumberFormatException nfe) {
			if (this.getId().equalsIgnoreCase("other") || this.getId().equalsIgnoreCase("noinfo"))
				return 1; //positive number  
			else
				return 0;
		}
	}
	
}
