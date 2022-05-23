def validateTLE(tle):
    """Check to see if a TLE is valid."""
    #TODO: COUNT NEWLINES IN TLE
    tle_lines = tle.strip().splitlines()
    name = tle_lines[0].strip()
    first_line = tle_lines[1].strip()
    second_line = tle_lines[2].strip()

    if (len(name) > 24):
        raise ValueError("TLE has a name longer than 24 characters.")

    if not (len(first_line) >= 64 and
        first_line.startswith('1 ') and
        first_line[8] == ' ' and
        first_line[23] == '.' and
        first_line[32] == ' ' and
        first_line[34] == '.' and
        first_line[43] == ' ' and
        first_line[52] == ' ' and
        first_line[61] == ' ' and
        first_line[63] == ' '):
        raise ValueError("TLE first line is invalid.")

    print(len(second_line))

    #if not (len(second_line) >= 69 and
    #if not (second_line.startswith('2 ') and
    #    second_line[7] == ' ' and
    #    second_line[11] == '.' and
    #    second_line[16] == ' ' and
    #    second_line[20] == '.' and
    #    second_line[25] == ' ' and
    #    second_line[33] == ' ' and
    #    #second_line[37] == '.'):# and
    #    second_line[42] == ' ' and
    #    second_line[46] == '.' and
    #    second_line[51] == ' '):
    #    raise ValueError("TLE second line is invalid.")

    if not (first_line[2:7] == second_line[2:7] ):
        raise ValueError("Satellite number in TLE lines one and two do not match.")
        
    return name, first_line, second_line

def compute_calendar_date(jd_integer, julian_before=None):
    """Convert Julian day ``jd_integer`` into a calendar (year, month, day).
    Uses the proleptic Gregorian calendar unless ``julian_before`` is
    set to a specific Julian day, in which case the Julian calendar is
    used for dates older than that.
    """
    use_gregorian = (julian_before is None) or (jd_integer >= julian_before)

    # See the Explanatory Supplement to the Astronomical Almanac 15.11.
    f = jd_integer + 1401
    f += use_gregorian * ((4 * jd_integer + 274277) // 146097 * 3 // 4 - 38)
    e = 4 * f + 3
    g = e % 1461 // 4
    h = 5 * g + 2
    day = h % 153 // 5 + 1
    month = (h // 153 + 2) % 12 + 1
    year = e // 1461 - 4716 + (12 + 2 - month) // 12
    return year, month, day