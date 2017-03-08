/**
 * A data element to keep information
 * @author raunak
 *
 */
public class CVECountBySeverity {
	
	private int low;
	private int medium;
	private int high;
	private int all;
	
	// default constructor
	public CVECountBySeverity(){
		low = 0;
		medium = 0;
		high = 0;
		all = 0;
	}
	// parameterized constructor
	public CVECountBySeverity(int lowLevel, int mediumLevel, int highLevel, int allLevels){
		low = lowLevel;
		medium = mediumLevel;
		high = highLevel;
		all = allLevels;
	}
	
	// Getters
	public int getLow() {
		return low;
	}

	public int getMedium() {
		return medium;
	}

	public int getHigh() {
		return high;
	}

	public int getAll() {
		return all;
	}




}
	
