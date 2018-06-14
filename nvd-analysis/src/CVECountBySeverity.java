/**
 * A data element to keep information
 * @author raunak
 *
 */
public class CVECountBySeverity {

	//varaibles for counting the different types of severitie levels
	private int low;
	private int medium;
	private int high;
	private int all;
	
	/** default constructor */
	public CVECountBySeverity(){
		low = 0;
		medium = 0;
		high = 0;
		all = 0;
	}
	/** parameterized constructor, setting all the class attributes to desired presets
	 * @param Count number of low level CVEs
	 * @param Count number of medium level CVEs
	 * @param Count number of high level CVEs
	 * @param Count number of all CVEs
	*/
	public CVECountBySeverity(int lowLevel, int mediumLevel, int highLevel, int allLevels){
		low = lowLevel;
		medium = mediumLevel;
		high = highLevel;
		all = allLevels;
	}
	
	/** Returns the number of low level CVEs
	 *  @return Count amount of low level CVEs
	 */
	public int getLow() {
		return low;
	}
	
	/** Returns the number of medium level CVEs
	 *  @return Count amount of medium level severities
	 */
	public int getMedium() {
		return medium;
	}

	/** Returns the number of high level CVEs
         *  @return Count amount of high level CVEs
         */
	public int getHigh() {
		return high;
	}

	/** Returns the number of all level CVEs
         *  @return Count amount of all level CVEs
         */
	public int getAll() {
		return all;
	}




}
	
