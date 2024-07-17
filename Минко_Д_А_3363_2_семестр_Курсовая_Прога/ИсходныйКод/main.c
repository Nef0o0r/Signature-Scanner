#include <stdio.h>
#include <stddef.h>
#include <windows.h>

int path(char* PathFileTxt, char* PathFileExe)
{
    if(PathFileTxt == NULL)
    {
        printf("Pointer ERROR!\n");
        return 1;
    }
    if (PathFileExe == NULL)
    {
        printf("Pointer ERROR!\n");
        return 2;
    }
    if (printf("Enter the path for the \"Antivirus database\":\n") < 0)
    {
        printf("\nPrintf ERROR!\n");
        return 3;
    }
    if (scanf("%259[^\n]%*c", PathFileTxt) != 1)
    {
        printf("\nScanf ERROR!\n");
        return 4;
    }
    if (printf("\nEnter the path for the \"File to be checked\":\n") < 0)
    {
        printf("\nPrintf ERROR!\n");
        return 5;
    }
    if (scanf("%259[^\n]%*c", PathFileExe) != 1)
    {
        printf("\nScanf ERROR!\n");
        return 6;
    }
    if (printf("\n") < 0)
    {
        printf("\nPrintf ERROR!\n");
        return 7;
    }
    return 0;
}

struct VirusInfo
{
    char Name[50];
    size_t Move;
    unsigned char Sign[8];
};

int main()
{
    FILE *FilenameExe;
    FILE *FilenameTxt;
    unsigned char Signature[8];
    char PathFileTxt[MAX_PATH];
    char PathFileExe[MAX_PATH];
    unsigned char MZ[2];
    long int TMP = 0;
    size_t i = 0;
    struct VirusInfo Virus;

    if(printf("\"Signature scanner\" App (by Minko Dmitriy)\n\n") < 0)
    {
        printf("\nPrintf ERROR!\n");
        return 1;
    }
    if(path(PathFileTxt, PathFileExe) != 0)
    {
        printf("Input file paths ERROR!\n");
        return 2;
    }

    FilenameTxt = fopen(PathFileTxt, "r");
    if (FilenameTxt == NULL)
    {
        printf("ERROR opening the \"Antivirus database\" for reading!\n");
        return 3;
    }
    if(fscanf(FilenameTxt, "%49[^\n]", Virus.Name) != 1)
    {
        printf("Virus name reading ERROR!\n");
        fclose(FilenameTxt);
        return 4;
    }
    if(fscanf(FilenameTxt, "%zu", &Virus.Move) != 1)
    {
        printf("Virus signature offset reading ERROR!\n");
        fclose(FilenameTxt);
        return 5;
    }
    for (i = 0; i < (sizeof(Virus.Sign)/sizeof(Virus.Sign[0])); i++)
    {
        if (fscanf(FilenameTxt,"%02hhx", &Virus.Sign[i]) != 1)
        {
            printf("ERROR reading signature from \"Antivirus database\"!");
            fclose(FilenameTxt);
            return 6;
        }
    }
    if (fclose(FilenameTxt) != 0)
    {
        printf("ERROR closing the \"Antivirus database\"!\n");
        return 7;
    }
    FilenameExe = fopen(PathFileExe, "rb");
    if (FilenameExe == NULL)
    {
        printf("ERROR opening the \"File to be checked\" for reading!\n");
        return 8;
    }

    if (fread(MZ, sizeof(MZ)/sizeof(MZ[0]), sizeof(MZ[0]), FilenameExe) != 1)
    {
        printf("ERROR reading signature from binary file!\n");
        fclose(FilenameExe);
        return 9;
    }
    if ((MZ[0] != 'M')||(MZ[1] != 'Z'))
    {
        if (printf("It's not a virus.\n") < 0)
        {
            printf("\nPrintf ERROR!\n");
            fclose(FilenameExe);
            return 10;
        }
        if(fclose(FilenameExe) != 0)
        {
            printf("ERROR closing the \"File to be checked\"!\n");
            return 11;
        };
        return 0;
    }
    if (fseek(FilenameExe, 0, SEEK_END) != 0)
    {
        printf("ERROR in fseek function!\n");
        fclose(FilenameExe);
        return 12;
    }
    TMP = ftell(FilenameExe);
    if (TMP == -1)
    {
        printf("ERROR obtaining the size of the \"File to be checked\"!\n");
        fclose(FilenameExe);
        return 13;
    }
    if (TMP < (Virus.Move + (sizeof(Virus.Sign)/sizeof(Virus.Sign[0]) - 1)))
    {
        if (printf("It's not a virus.\n") < 0)
        {
            printf("\nPrintf ERROR!\n");
            fclose(FilenameExe);
            return 14;
        }
        if(fclose(FilenameExe) != 0)
        {
            printf("ERROR closing the \"File to be checked\"!\n");
            return 15;
        };
        return 0;
    }
    if (fseek(FilenameExe, Virus.Move, SEEK_SET) != 0)
    {
        printf("ERROR in fseek function!\n");
        fclose(FilenameExe);
        return 16;
    }
    if(fread(Signature, sizeof(Signature)/sizeof(Signature[0]), sizeof(Signature[0]), FilenameExe) != 1)
    {
        printf("ERROR reading the signature from the binary file!\n");
        fclose(FilenameExe);
        return 17;
    }
    TMP = 0;

    for (i = 0; i < (sizeof(Signature)/sizeof(Signature[0])); i++)
    {
        if(Signature[i] != Virus.Sign[i])
        {
            if (printf("It's not a virus.\n") < 0)
            {
                printf("\nPrintf ERROR!\n");
                return 18;
            }
            if (fclose(FilenameExe) != 0)
            {
                printf("ERROR closing the \"File to be checked\" file!\n");
                return 19;
            }
            return 0;
        }
        TMP++;
    }
    if(TMP == 8)
    {
        if (printf("This is a virus called \"%s\"\n", Virus.Name) < 0)
        {
            printf("Printf ERROR!\n");
            return 20;
        }
    }
    if (fclose(FilenameExe) != 0)
    {
        printf("ERROR closing the \"File to be checked\" file!\n");
        return 21;
    }
    return 0;
}
