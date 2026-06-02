#include "ALINK.H"

void loadcoff(FILE *objfile)
{
    unsigned char headbuf[20];
    unsigned char buf[100];
    PUCHAR bigbuf;
    PUCHAR stringList;
    UINT thiscpu;
    UINT numSect;
    UINT headerSize;
    UINT symbolPtr;
    UINT numSymbols;
    UINT stringPtr;
    UINT stringSize;
    UINT stringOfs;
    UINT i, j, k;
    UINT fileStart;
    UINT minseg;
    UINT numrel;
    UINT relofs;
    UINT relshift;
    UINT sectname;
    long sectorder;
    PCOFFSYM sym = NULL;
    UINT combineType;
    PPUBLIC pubdef;
    PCOMDAT comdat;
    PCHAR comdatsym;
    PSORTENTRY listnode;

    nummods++;
    minseg = segcount;
    fileStart = ftell(objfile);

    if (fread(headbuf, 1, 20, objfile) != 20)
    {
	printf("Unable to read from file\n");
	exit(1);
    }
    thiscpu = headbuf[0] + 256 * headbuf[1];
    if (!thiscpu)
    {
	/* if we've got an import module, start at the beginning */
	fseek(objfile, fileStart, SEEK_SET);
	/* and load it */
	loadCoffImport(objfile);
	return;
    }

    if ((thiscpu < 0x14c) || (thiscpu > 0x14e))
    {
	printf("Unsupported CPU type for module\n");
	exit(1);
    }
    numSect =
	headbuf[PE_NUMOBJECTS - PE_MACHINEID] + 256 * headbuf[PE_NUMOBJECTS - PE_MACHINEID + 1];

    symbolPtr = headbuf[PE_SYMBOLPTR - PE_MACHINEID] +
		(headbuf[PE_SYMBOLPTR - PE_MACHINEID + 1] << 8) +
		(headbuf[PE_SYMBOLPTR - PE_MACHINEID + 2] << 16) +
		(headbuf[PE_SYMBOLPTR - PE_MACHINEID + 3] << 24);

    numSymbols = headbuf[PE_NUMSYMBOLS - PE_MACHINEID] +
		 (headbuf[PE_NUMSYMBOLS - PE_MACHINEID + 1] << 8) +
		 (headbuf[PE_NUMSYMBOLS - PE_MACHINEID + 2] << 16) +
		 (headbuf[PE_NUMSYMBOLS - PE_MACHINEID + 3] << 24);

    if (headbuf[PE_HDRSIZE - PE_MACHINEID] | headbuf[PE_HDRSIZE - PE_MACHINEID + 1])
    {
	printf("warning, optional header discarded\n");
	headerSize =
	    headbuf[PE_HDRSIZE - PE_MACHINEID] + 256 * headbuf[PE_HDRSIZE - PE_MACHINEID + 1];
    }
    else
	headerSize = 0;
    headerSize += PE_BASE_HEADER_SIZE - PE_MACHINEID;

    stringPtr = symbolPtr + numSymbols * PE_SYMBOL_SIZE;
    if (stringPtr)
    {
	fseek(objfile, fileStart + stringPtr, SEEK_SET);
	if (fread(buf, 1, 4, objfile) != 4)
	{
	    printf("Invalid COFF object file, unable to read string table size\n");
	    exit(1);
	}
	stringSize = buf[0] + (buf[1] << 8) + (buf[2] << 16) + (buf[3] << 24);
	if (!stringSize)
	    stringSize = 4;
	if (stringSize < 4)
	{
	    printf("Invalid COFF object file, bad string table size %u\n", stringSize);
	    exit(1);
	}
	stringPtr += 4;
	stringSize -= 4;
    }
    else
    {
	stringSize = 0;
    }
    if (stringSize)
    {
	stringList = (PUCHAR)checkMalloc(stringSize);
	if (fread(stringList, 1, stringSize, objfile) != stringSize)
	{
	    printf("Invalid COFF object file, unable to read string table\n");
	    exit(1);
	}
	if (stringList[stringSize - 1])
	{
	    printf("Invalid COFF object file, last string unterminated\n");
	    exit(1);
	}
    }
    else
    {
	stringList = NULL;
    }

    if (symbolPtr && numSymbols)
    {
	fseek(objfile, fileStart + symbolPtr, SEEK_SET);
	sym = (PCOFFSYM)checkMalloc(sizeof(COFFSYM) * numSymbols);
	for (i = 0; i < numSymbols; i++)
	{
	    if (fread(buf, 1, PE_SYMBOL_SIZE, objfile) != PE_SYMBOL_SIZE)
	    {
		printf("Invalid COFF object file, unable to read symbols\n");
		exit(1);
	    }
	    if (buf[0] | buf[1] | buf[2] | buf[3])
	    {
		sym[i].name = (PUCHAR)checkMalloc(9);
		memcpy(sym[i].name, buf, 8);
		sym[i].name[8] = 0;
	    }
	    else
	    {
		stringOfs = buf[4] + (buf[5] << 8) + (buf[6] << 16) + (buf[7] << 24);
		if (stringOfs < 4)
		{
		    printf("Invalid COFF object file bad symbol location\n");
		    exit(1);
		}
		stringOfs -= 4;
		if (stringOfs >= stringSize)
		{
		    printf("Invalid COFF object file bad symbol location\n");
		    exit(1);
		}
		sym[i].name = checkStrdup(stringList + stringOfs);
	    }
	    if (!case_sensitive)
	    {
		strupr(sym[i].name);
	    }

	    sym[i].value = buf[8] + (buf[9] << 8) + (buf[10] << 16) + (buf[11] << 24);
	    sym[i].section = buf[12] + (buf[13] << 8);
	    sym[i].type = buf[14] + (buf[15] << 8);
	    sym[i].class = buf[16];
	    sym[i].extnum = -1;
	    sym[i].numAuxRecs = buf[17];
	    sym[i].isComDat = FALSE;

	    switch (sym[i].class)
	    {
	    case COFF_SYM_SECTION: /* section symbol */
		if (sym[i].section < -1)
		{
		    break;
		}
		/* section symbols declare an extern always, so can use in relocs */
		/* they may also include a PUBDEF */
		externs = (PEXTREC)checkRealloc(externs, (extcount + 1) * sizeof(EXTREC));
		externs[extcount].name = sym[i].name;
		externs[extcount].pubdef = NULL;
		externs[extcount].modnum = 0;
		externs[extcount].flags = EXT_NOMATCH;
		sym[i].extnum = extcount;
		extcount++;
		if (sym[i].section != 0) /* if the section is defined here, make public */
		{
		    pubdef = (PPUBLIC)checkMalloc(sizeof(PUBLIC));
		    pubdef->grpnum = -1;
		    pubdef->typenum = 0;
		    pubdef->modnum = 0;
		    pubdef->aliasName = NULL;
		    pubdef->ofs = sym[i].value;

		    if (sym[i].section == -1)
		    {
			pubdef->segnum = -1;
		    }
		    else
		    {
			pubdef->segnum = minseg + sym[i].section - 1;
		    }
		    if ((listnode = binarySearch(publics, pubcount, sym[i].name)) != NULL)
		    {
			for (j = 0; j < listnode->count; ++j)
			{
			    if (((PPUBLIC)listnode->object[j])->modnum == pubdef->modnum)
			    {
				if (!((PPUBLIC)listnode->object[j])->aliasName)
				{
				    printf("Duplicate public symbol %s\n", sym[i].name);
				    exit(1);
				}
				free(((PPUBLIC)listnode->object[j])->aliasName);
				(*((PPUBLIC)listnode->object[j])) = (*pubdef);
				pubdef = NULL;
				break;
			    }
			}
		    }
		    if (pubdef)
		    {
			sortedInsert(&publics, &pubcount, sym[i].name, pubdef);
		    }
		}
	    case COFF_SYM_STATIC: /* allowed, but ignored for now as we only want to process if
				     required */
	    case COFF_SYM_LABEL:
	    case COFF_SYM_FILE:
	    case COFF_SYM_FUNCTION:
	    case COFF_SYM_EXTERNAL:
		break;
	    default:
		printf("unsupported symbol class %02X for symbol %s\n", sym[i].class, sym[i].name);
		exit(1);
	    }
	    if (sym[i].numAuxRecs)
	    {
		sym[i].auxRecs = (PUCHAR)checkMalloc(sym[i].numAuxRecs * PE_SYMBOL_SIZE);
	    }
	    else
	    {
		sym[i].auxRecs = NULL;
	    }

	    /* read in the auxillary records for this symbol */
	    for (j = 0; j < sym[i].numAuxRecs; j++)
	    {
		if (fread(sym[i].auxRecs + j * PE_SYMBOL_SIZE, 1, PE_SYMBOL_SIZE, objfile) !=
		    PE_SYMBOL_SIZE)
		{
		    printf("Invalid COFF object file\n");
		    exit(1);
		}
		sym[i + j + 1].name = NULL;
		sym[i + j + 1].numAuxRecs = 0;
		sym[i + j + 1].value = 0;
		sym[i + j + 1].section = -1;
		sym[i + j + 1].type = 0;
		sym[i + j + 1].class = 0;
		sym[i + j + 1].extnum = -1;
	    }
	    i += j;
	}
    }
    for (i = 0; i < numSect; i++)
    {
	fseek(objfile, fileStart + headerSize + i * PE_OBJECTENTRY_SIZE, SEEK_SET);
	if (fread(buf, 1, PE_OBJECTENTRY_SIZE, objfile) != PE_OBJECTENTRY_SIZE)
	{
	    printf("Invalid COFF object file, unable to read section header\n");
	    exit(1);
	}
	/* virtual size is also the offset of the data into the segment */
	/*
	  if(buf[PE_OBJECT_VIRTSIZE]|buf[PE_OBJECT_VIRTSIZE+1]|buf[PE_OBJECT_VIRTSIZE+2]
	  |buf[PE_OBJECT_VIRTSIZE+3])
	  {
	  printf("Invalid COFF object file, section has non-zero virtual size\n");
	  exit(1);
	  }
	*/
	buf[8] = 0; /* null terminate name */
	/* get shift value for relocs */
	relshift = buf[PE_OBJECT_VIRTADDR] + (buf[PE_OBJECT_VIRTADDR + 1] << 8) +
		   (buf[PE_OBJECT_VIRTADDR + 2] << 16) + (buf[PE_OBJECT_VIRTADDR + 3] << 24);

	if (buf[0] == '/')
	{
	    sectname = strtoul(buf + 1, (char **)&bigbuf, 10);
	    if (*bigbuf)
	    {
		printf("Invalid COFF object file, invalid number %s\n", buf + 1);
		exit(1);
	    }
	    if (sectname < 4)
	    {
		printf("Invalid COFF object file\n");
		exit(1);
	    }
	    sectname -= 4;
	    if (sectname >= stringSize)
	    {
		printf("Invalid COFF object file\n");
		exit(1);
	    }
	    namelist = (PPCHAR)checkRealloc(namelist, (namecount + 1) * sizeof(PCHAR));
	    namelist[namecount] = checkStrdup(stringList + sectname);
	    sectname = namecount;
	    namecount++;
	}
	else
	{
	    namelist = (PPCHAR)checkRealloc(namelist, (namecount + 1) * sizeof(PCHAR));
	    namelist[namecount] = checkStrdup(buf);

	    sectname = namecount;
	    namecount++;
	}
	if (strchr(namelist[sectname], '$'))
	{
	    /* if we have a grouped segment, sort by original name */
	    sectorder = sectname;
	    /* and get real name, without $ sort section */
	    namelist = (PPCHAR)checkRealloc(namelist, (namecount + 1) * sizeof(PCHAR));
	    namelist[namecount] = checkStrdup(namelist[sectname]);
	    *(strchr(namelist[namecount], '$')) = 0;
	    sectname = namecount;
	    namecount++;
	}
	else
	{
	    sectorder = -1;
	}

	numrel = buf[PE_OBJECT_NUMREL] + (buf[PE_OBJECT_NUMREL + 1] << 8);
	relofs = buf[PE_OBJECT_RELPTR] + (buf[PE_OBJECT_RELPTR + 1] << 8) +
		 (buf[PE_OBJECT_RELPTR + 2] << 16) + (buf[PE_OBJECT_RELPTR + 3] << 24);

	seglist = (PPSEG)checkRealloc(seglist, (segcount + 1) * sizeof(PSEG));
	seglist[segcount] = (PSEG)checkMalloc(sizeof(SEG));

	seglist[segcount]->nameindex = sectname;
	seglist[segcount]->orderindex = sectorder;
	seglist[segcount]->classindex = -1;
	seglist[segcount]->overlayindex = -1;
	seglist[segcount]->length = buf[PE_OBJECT_RAWSIZE] + (buf[PE_OBJECT_RAWSIZE + 1] << 8) +
				    (buf[PE_OBJECT_RAWSIZE + 2] << 16) +
				    (buf[PE_OBJECT_RAWSIZE + 3] << 24);

	seglist[segcount]->attr = SEG_PUBLIC | SEG_USE32;
	seglist[segcount]->winFlags = buf[PE_OBJECT_FLAGS] + (buf[PE_OBJECT_FLAGS + 1] << 8) +
				      (buf[PE_OBJECT_FLAGS + 2] << 16) +
				      (buf[PE_OBJECT_FLAGS + 3] << 24);
	seglist[segcount]->base = buf[PE_OBJECT_RAWPTR] + (buf[PE_OBJECT_RAWPTR + 1] << 8) +
				  (buf[PE_OBJECT_RAWPTR + 2] << 16) +
				  (buf[PE_OBJECT_RAWPTR + 3] << 24);

	if (seglist[segcount]->winFlags & WINF_ALIGN_NOPAD)
	{
	    seglist[segcount]->winFlags &= (0xffffffff - WINF_ALIGN);
	    seglist[segcount]->winFlags |= WINF_ALIGN_BYTE;
	}

	switch (seglist[segcount]->winFlags & WINF_ALIGN)
	{
	case WINF_ALIGN_BYTE:
	    seglist[segcount]->attr |= SEG_BYTE;
	    break;
	case WINF_ALIGN_WORD:
	    seglist[segcount]->attr |= SEG_WORD;
	    break;
	case WINF_ALIGN_DWORD:
	    seglist[segcount]->attr |= SEG_DWORD;
	    break;
	case WINF_ALIGN_8:
	    seglist[segcount]->attr |= SEG_8BYTE;
	    break;
	case WINF_ALIGN_PARA:
	    seglist[segcount]->attr |= SEG_PARA;
	    break;
	case WINF_ALIGN_32:
	    seglist[segcount]->attr |= SEG_32BYTE;
	    break;
	case WINF_ALIGN_64:
	    seglist[segcount]->attr |= SEG_64BYTE;
	    break;
	case 0:
	    seglist[segcount]->attr |= SEG_PARA; /* default */
	    break;
	default:
	    printf("Invalid COFF object file, bad section alignment %08X\n",
		   seglist[segcount]->winFlags);
	    exit(1);
	}

	/* invert all negative-logic flags */
	seglist[segcount]->winFlags ^= WINF_NEG_FLAGS;
	/* remove .debug sections */
	if (!stricmp(namelist[sectname], ".debug"))
	{
	    seglist[segcount]->winFlags |= WINF_REMOVE;
	    seglist[segcount]->length = 0;
	    numrel = 0;
	}

	if (seglist[segcount]->winFlags & WINF_COMDAT)
	{
	    printf("COMDAT section %s\n", namelist[sectname]);
	    comdat = (PCOMDAT)checkMalloc(sizeof(COMDATREC));
	    combineType = 0;
	    comdat->linkwith = 0;
	    for (j = 0; j < numSymbols; j++)
	    {
		if (!sym[j].name)
		    continue;
		if (sym[j].section == (i + 1))
		{
		    if (sym[j].numAuxRecs != 1)
		    {
			printf("Invalid COMDAT section reference\n");
			exit(1);
		    }
		    printf("Section %s ", sym[j].name);
		    combineType = sym[j].auxRecs[14];
		    comdat->linkwith = sym[j].auxRecs[12] + (sym[j].auxRecs[13] << 8) + minseg - 1;
		    printf("Combine type %i ", sym[j].auxRecs[14]);
		    printf("Link alongside section %u", comdat->linkwith);

		    break;
		}
	    }
	    if (j == numSymbols)
	    {
		printf("Invalid COMDAT section\n");
		exit(1);
	    }
	    for (j++; j < numSymbols; j++)
	    {
		if (!sym[j].name)
		    continue;
		if (sym[j].section == (i + 1))
		{
		    if (sym[j].numAuxRecs)
		    {
			printf("Invalid COMDAT symbol\n");
			exit(1);
		    }

		    printf("COMDAT Symbol %s\n", sym[j].name);
		    comdatsym = sym[j].name;
		    sym[j].isComDat = TRUE;
		    break;
		}
	    }
	    /* associative sections don't have a name */
	    if (j == numSymbols)
	    {
		if (combineType != 5)
		{
		    printf("\nInvalid COMDAT section\n");
		    exit(1);
		}
		else
		{
		    printf("\n");
		}
		comdatsym = ""; /* dummy name */
	    }
	    comdat->segnum = segcount;
	    comdat->combineType = combineType;

	    printf("COMDATs not yet supported\n");
	    exit(1);

	    printf("Combine types for duplicate COMDAT symbol %s do not match\n", comdatsym);
	    exit(1);
	}

	if (seglist[segcount]->length)
	{
	    seglist[segcount]->data = (PUCHAR)checkMalloc(seglist[segcount]->length);

	    seglist[segcount]->datmask = (PUCHAR)checkMalloc((seglist[segcount]->length + 7) / 8);

	    if (seglist[segcount]->base)
	    {
		fseek(objfile, fileStart + seglist[segcount]->base, SEEK_SET);
		if (fread(seglist[segcount]->data, 1, seglist[segcount]->length, objfile) !=
		    seglist[segcount]->length)
		{
		    printf("Invalid COFF object file\n");
		    exit(1);
		}
		for (j = 0; j < (seglist[segcount]->length + 7) / 8; j++)
		    seglist[segcount]->datmask[j] = 0xff;
	    }
	    else
	    {
		for (j = 0; j < (seglist[segcount]->length + 7) / 8; j++)
		    seglist[segcount]->datmask[j] = 0;
	    }
	}
	else
	{
	    seglist[segcount]->data = NULL;
	    seglist[segcount]->datmask = NULL;
	}

	if (numrel)
	    fseek(objfile, fileStart + relofs, SEEK_SET);
	for (j = 0; j < numrel; j++)
	{
	    if (fread(buf, 1, PE_RELOC_SIZE, objfile) != PE_RELOC_SIZE)
	    {
		printf("Invalid COFF object file, unable to read reloc table\n");
		exit(1);
	    }
	    relocs = (PPRELOC)checkRealloc(relocs, (fixcount + 1) * sizeof(PRELOC));
	    relocs[fixcount] = (PRELOC)checkMalloc(sizeof(RELOC));
	    /* get address to relocate */
	    relocs[fixcount]->ofs = buf[0] + (buf[1] << 8) + (buf[2] << 16) + (buf[3] << 24);
	    relocs[fixcount]->ofs -= relshift;
	    /* get segment */
	    relocs[fixcount]->segnum = i + minseg;
	    relocs[fixcount]->disp = 0;
	    /* get relocation target external index */
	    relocs[fixcount]->target = buf[4] + (buf[5] << 8) + (buf[6] << 16) + (buf[7] << 24);
	    if (relocs[fixcount]->target >= numSymbols)
	    {
		printf("Invalid COFF object file, undefined symbol\n");
		exit(1);
	    }
	    k = relocs[fixcount]->target;
	    relocs[fixcount]->ttype = REL_EXTONLY; /* assume external reloc */
	    if (sym[k].extnum < 0)
	    {
		switch (sym[k].class)
		{
		case COFF_SYM_EXTERNAL:
		    /* global symbols declare an extern when used in relocs */
		    externs = (PEXTREC)checkRealloc(externs, (extcount + 1) * sizeof(EXTREC));
		    externs[extcount].name = sym[k].name;
		    externs[extcount].pubdef = NULL;
		    externs[extcount].modnum = 0;
		    externs[extcount].flags = EXT_NOMATCH;
		    sym[k].extnum = extcount;
		    extcount++;
		    /* they may also include a COMDEF or a PUBDEF */
		    /* this is dealt with after all sections loaded, to cater for COMDAT symbols */
		    break;
		case COFF_SYM_STATIC: /* static symbol */
		case COFF_SYM_LABEL:  /* code label symbol */
		    if (sym[k].section < -1)
		    {
			printf("cannot relocate against a debug info symbol\n");
			exit(1);
			break;
		    }
		    if (sym[k].section == 0)
		    {
			if (sym[k].value)
			{
			    externs =
				(PEXTREC)checkRealloc(externs, (extcount + 1) * sizeof(EXTREC));
			    externs[extcount].name = sym[k].name;
			    externs[extcount].pubdef = NULL;
			    externs[extcount].modnum = nummods;
			    externs[extcount].flags = EXT_NOMATCH;
			    sym[k].extnum = extcount;
			    extcount++;

			    comdefs =
				(PPCOMREC)checkRealloc(comdefs, (comcount + 1) * sizeof(PCOMREC));
			    comdefs[comcount] = (PCOMREC)checkMalloc(sizeof(COMREC));
			    comdefs[comcount]->length = sym[k].value;
			    comdefs[comcount]->isFar = FALSE;
			    comdefs[comcount]->name = sym[k].name;
			    comdefs[comcount]->modnum = nummods;
			    comcount++;
			}
			else
			{
			    printf("Undefined symbol %s\n", sym[k].name);
			    exit(1);
			}
		    }
		    else
		    {
			/* update relocation information to reflect symbol */
			relocs[fixcount]->ttype = REL_SEGDISP;
			relocs[fixcount]->disp = sym[k].value;
			if (sym[k].section == -1)
			{
			    /* absolute symbols have section=-1 */
			    relocs[fixcount]->target = -1;
			}
			else
			{
			    /* else get real number of section */
			    relocs[fixcount]->target = sym[k].section + minseg - 1;
			}
		    }
		    break;
		default:
		    printf("undefined symbol class 0x%02X for symbol %s\n", sym[k].class,
			   sym[k].name);
		    exit(1);
		}
	    }
	    if (relocs[fixcount]->ttype == REL_EXTONLY)
	    {
		/* set relocation target to external if sym is external */
		relocs[fixcount]->target = sym[k].extnum;
	    }

	    /* frame is current segment (only relevant for non-FLAT output) */
	    relocs[fixcount]->ftype = REL_SEGFRAME;
	    relocs[fixcount]->frame = i + minseg;
	    /* set relocation type */
	    switch (buf[8] + (buf[9] << 8))
	    {
	    case COFF_FIX_DIR32:
		relocs[fixcount]->rtype = FIX_OFS32;
		break;
	    case COFF_FIX_RVA32:
		relocs[fixcount]->rtype = FIX_RVA32;
		break;
		/*
		  case 0x0a: -
		  break;
		  case 0x0b:
		  break;
		*/
	    case COFF_FIX_REL32:
		relocs[fixcount]->rtype = FIX_SELF_OFS32;
		break;
	    default:
		printf("unsupported COFF relocation type %04X\n", buf[8] + (buf[9] << 8));
		exit(1);
	    }
	    fixcount++;
	}

	segcount++;
    }
    /* build PUBDEFs or COMDEFs for external symbols defined here that aren't COMDAT symbols. */
    for (i = 0; i < numSymbols; i++)
    {
	if (sym[i].class != COFF_SYM_EXTERNAL)
	    continue;
	if (sym[i].isComDat)
	    continue;
	if (sym[i].section < -1)
	{
	    break;
	}
	if (sym[i].section == 0)
	{
	    if (sym[i].value)
	    {
		comdefs = (PPCOMREC)checkRealloc(comdefs, (comcount + 1) * sizeof(PCOMREC));
		comdefs[comcount] = (PCOMREC)checkMalloc(sizeof(COMREC));
		comdefs[comcount]->length = sym[i].value;
		comdefs[comcount]->isFar = FALSE;
		comdefs[comcount]->name = sym[i].name;
		comdefs[comcount]->modnum = 0;
		comcount++;
	    }
	}
	else
	{
	    pubdef = (PPUBLIC)checkMalloc(sizeof(PUBLIC));
	    pubdef->grpnum = -1;
	    pubdef->typenum = 0;
	    pubdef->modnum = 0;
	    pubdef->aliasName = NULL;
	    pubdef->ofs = sym[i].value;

	    if (sym[i].section == -1)
	    {
		pubdef->segnum = -1;
	    }
	    else
	    {
		pubdef->segnum = minseg + sym[i].section - 1;
	    }
	    if ((listnode = binarySearch(publics, pubcount, sym[i].name)) != NULL)
	    {
		for (j = 0; j < listnode->count; ++j)
		{
		    if (((PPUBLIC)listnode->object[j])->modnum == pubdef->modnum)
		    {
			if (!((PPUBLIC)listnode->object[j])->aliasName)
			{
			    printf("Duplicate public symbol %s\n", sym[i].name);
			    exit(1);
			}
			free(((PPUBLIC)listnode->object[j])->aliasName);
			(*((PPUBLIC)listnode->object[j])) = (*pubdef);
			pubdef = NULL;
			break;
		    }
		}
	    }
	    if (pubdef)
	    {
		sortedInsert(&publics, &pubcount, sym[i].name, pubdef);
	    }
	}
    }

    if (symbolPtr && numSymbols)
	free(sym);
    if (stringList)
	free(stringList);
}

void loadCoffImport(FILE *objfile)
{
    UINT thiscpu;

    if (fread(buf, 1, 20, objfile) != 20)
    {
	printf("Unable to read from file\n");
	exit(1);
    }

    if (buf[0] || buf[1] || (buf[2] != 0xff) || (buf[3] != 0xff))
    {
	printf("Invalid Import entry\n");
	exit(1);
    }
    /* get CPU type */
    thiscpu = buf[6] + 256 * buf[7];
    printf("Import CPU=%04X\n", thiscpu);

    if ((thiscpu < 0x14c) || (thiscpu > 0x14e))
    {
	printf("Unsupported CPU type for module\n");
	exit(1);
    }
}
