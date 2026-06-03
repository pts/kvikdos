#include "ALINK.H"

void loadCoffLib(FILE *libfile, PCHAR libname)
{
    UINT i, j;
    UINT numsyms;
    UINT modpage;
    UINT memberSize;
    UINT startPoint;
    PUCHAR endptr;
    PLIBFILE p;
    PCHAR name;
    PUCHAR modbuf;
    PSORTENTRY symlist = NULL;
    int x;

    libfiles = checkRealloc(libfiles, (libcount + 1) * sizeof(LIBFILE));
    p = &libfiles[libcount];
    p->filename = checkMalloc(strlen(libname) + 1);
    strcpy(p->filename, libname);
    startPoint = ftell(libfile);

    if (fread(buf, 1, 8, libfile) != 8)
    {
	printf("Error reading from file\n");
	exit(1);
    }
    buf[8] = 0;
    /* complain if file header is wrong */
    if (strcmp(buf, "!<arch>\n"))
    {
	printf("Invalid library file format - bad file header\n");
	printf("\"%s\"\n", buf);

	exit(1);
    }
    /* read archive member header */
    if (fread(buf, 1, 60, libfile) != 60)
    {
	printf("Error reading from file\n");
	exit(1);
    }
    if ((buf[58] != 0x60) || (buf[59] != '\n'))
    {
	printf("Invalid library file format - bad member signature\n");
	exit(1);
    }
    buf[16] = 0;
    /* check name of first linker member */
    if (strcmp(buf, "/               ")) /* 15 spaces */
    {
	printf("Invalid library file format - bad member name\n");
	exit(1);
    }
    buf[58] = 0;

    /* strip trailing spaces from size */
    endptr = buf + 57;
    while ((endptr > (buf + 48)) && isspace(*endptr))
    {
	*endptr = 0;
	endptr--;
    }

    /* get size */
    errno = 0;
    memberSize = strtoul(buf + 48, (PPCHAR)&endptr, 10);
    if (errno || (*endptr))
    {
	printf("Invalid library file format - bad member size\n");
	exit(1);
    }
    if ((memberSize < 4) && memberSize)
    {
	printf("Invalid library file format - bad member size\n");
	exit(1);
    }
    if (!memberSize)
    {
	numsyms = 0;
    }
    else
    {
	if (fread(buf, 1, 4, libfile) != 4)
	{
	    printf("Error reading from file\n");
	    exit(1);
	}
	numsyms = buf[3] + (buf[2] << 8) + (buf[1] << 16) + (buf[0] << 24);
    }
    printf("%u symbols\n", numsyms);
    modbuf = (PUCHAR)checkMalloc(numsyms * 4);

    if (numsyms)
    {
	if (fread(modbuf, 1, 4 * numsyms, libfile) != 4 * numsyms)
	{
	    printf("Error reading from file\n");
	    exit(1);
	}
	symlist = (PSORTENTRY)checkMalloc(sizeof(SORTENTRY) * numsyms);
    }

    for (i = 0; i < numsyms; i++)
    {
	modpage = modbuf[3 + i * 4] + (modbuf[2 + i * 4] << 8) + (modbuf[1 + i * 4] << 16) +
		  (modbuf[i * 4] << 24);

	name = NULL;
	for (j = 0; TRUE; j++)
	{
	    if ((x = getc(libfile)) == EOF)
	    {
		printf("Error reading from file\n");
		exit(1);
	    }
	    if (!x)
		break;
	    name = (char *)checkRealloc(name, j + 2);
	    name[j] = x;
	    name[j + 1] = 0;
	}
	if (!name)
	{
	    printf("NULL name for symbol %u\n", i);
	    exit(1);
	}
	if (!case_sensitive)
	{
	    strupr(name);
	}

	symlist[i].id = name;
	symlist[i].count = modpage;
    }

    if (numsyms)
    {
	qsort(symlist, numsyms, sizeof(SORTENTRY), sortCompare);
	p->symbols = symlist;
	p->numsyms = numsyms;

	free(modbuf);
    }
    else
    {
	p->symbols = NULL;
	p->numsyms = 0;
    }

    /* move to an even byte boundary in the file */
    if (ftell(libfile) & 1)
    {
	fseek(libfile, 1, SEEK_CUR);
    }

    if (ftell(libfile) != (startPoint + 68 + memberSize))
    {
	printf("Invalid first linker member\n");
	printf("Pos=%08lX, should be %08X\n", ftell(libfile), startPoint + 68 + memberSize);

	exit(1);
    }

    printf("Loaded first linker member\n");

    startPoint = ftell(libfile);

    /* read archive member header */
    if (fread(buf, 1, 60, libfile) != 60)
    {
	printf("Error reading from file\n");
	exit(1);
    }
    if ((buf[58] != 0x60) || (buf[59] != '\n'))
    {
	printf("Invalid library file format - bad member signature\n");
	exit(1);
    }
    buf[16] = 0;
    /* check name of second linker member */
    if (!strcmp(buf, "/               ")) /* 15 spaces */
    {
	/* OK, so we've found it, now skip over */
	buf[58] = 0;

	/* strip trailing spaces from size */
	endptr = buf + 57;
	while ((endptr > (buf + 48)) && isspace(*endptr))
	{
	    *endptr = 0;
	    endptr--;
	}

	/* get size */
	errno = 0;
	memberSize = strtoul(buf + 48, (PPCHAR)&endptr, 10);
	if (errno || (*endptr))
	{
	    printf("Invalid library file format - bad member size\n");
	    exit(1);
	}
	if ((memberSize < 8) && memberSize)
	{
	    printf("Invalid library file format - bad member size\n");
	    exit(1);
	}

	/* move over second linker member */
	fseek(libfile, startPoint + 60 + memberSize, SEEK_SET);

	/* move to an even byte boundary in the file */
	if (ftell(libfile) & 1)
	{
	    fseek(libfile, 1, SEEK_CUR);
	}
    }
    else
    {
	fseek(libfile, startPoint, SEEK_SET);
    }

    startPoint = ftell(libfile);
    p->longnames = NULL;

    /* read archive member header */
    if (fread(buf, 1, 60, libfile) != 60)
    {
	printf("Error reading from file\n");
	exit(1);
    }
    if ((buf[58] != 0x60) || (buf[59] != '\n'))
    {
	printf("Invalid library file format - bad 3rd member signature\n");
	exit(1);
    }
    buf[16] = 0;
    /* check name of long names linker member */
    if (!strcmp(buf, "//              ")) /* 14 spaces */
    {
	buf[58] = 0;

	/* strip trailing spaces from size */
	endptr = buf + 57;
	while ((endptr > (buf + 48)) && isspace(*endptr))
	{
	    *endptr = 0;
	    endptr--;
	}

	/* get size */
	errno = 0;
	memberSize = strtoul(buf + 48, (PPCHAR)&endptr, 10);
	if (errno || (*endptr))
	{
	    printf("Invalid library file format - bad member size\n");
	    exit(1);
	}
	if (memberSize)
	{
	    p->longnames = (PUCHAR)checkMalloc(memberSize);
	    if (fread(p->longnames, 1, memberSize, libfile) != memberSize)
	    {
		printf("Error reading from file\n");
		exit(1);
	    }
	}
    }
    else
    {
	/* if no long names member, move back to member header */
	fseek(libfile, startPoint, SEEK_SET);
    }

    p->modsloaded = 0;
    p->modlist = checkMalloc(sizeof(unsigned short) * numsyms);
    p->libtype = 'C';
    p->blocksize = 1;
    p->flags = LIBF_CASESENSITIVE;
    libcount++;
}

void loadcofflibmod(PLIBFILE p, FILE *libfile)
{
    char *name;
    UINT ofs;

    if (fread(buf, 1, 60, libfile) != 60)
    {
	printf("Error reading from file\n");
	exit(1);
    }
    if ((buf[58] != 0x60) || (buf[59] != '\n'))
    {
	printf("Invalid library member header\n");
	exit(1);
    }
    buf[16] = 0;
    if (buf[0] == '/')
    {
	ofs = 15;
	while (isspace(buf[ofs]))
	{
	    buf[ofs] = 0;
	    ofs--;
	}

	ofs = strtoul(buf + 1, &name, 10);
	if (!buf[1] || *name)
	{
	    printf("Invalid string number \n");
	    exit(1);
	}
	name = p->longnames + ofs;
    }
    else
    {
	name = buf;
    }

    printf("Loading module %s\n", name);
    loadcoff(libfile);
}
