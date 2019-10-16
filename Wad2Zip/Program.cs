//Wad2Zip 1.0
//
//Converts .wad to .zip
//
//.wad is basically the same as .zip, but with different headers
//This tool simply converts the wad headers to the zip header format
//
//The only problem is that .zip requires a CRC32 hash
//KI .wad's contain a checksum, but it's not a standard CRC32, meaning it can't be used for zip
//Without a valid CRC32, all files will fail to extract
//
//This tool circumvents that problem by extracting the archive in-memory and calculating the crc32 of the extracted data (takes about 2 seconds because it's done in-memory)
//Then, instead of re-compressing the files, it uses the original deflate streams, but swaps the CRC with the neely-calculated one.
//With this, the original deflate streams will now work in a zip file, allowing the wad to be converted to zip
//
//It might seem weird to 're-compress' the wad after extracting it, but writing to disk is really slow (<2 seconds in-memory, about 2 minutes on-disk)
//If you want to save the extracted files, there's the argument -x which will instead write all files to disk ;)
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Compression;
using System.IO;
using System.Security.Cryptography;

namespace Wad2Zip
{
    class Program
    {

        public struct FileList
        {
            public string Filename;
            public uint Offset;
            public uint Size;
            public uint CompressedSize;
            public bool IsCompressed;
            public uint CRC;
            public byte[] Data;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Wad2Zip 1.0");
            System.Diagnostics.Stopwatch MainTimer = new System.Diagnostics.Stopwatch();
            MainTimer.Start();
            string wad = "";    //wad filename

            //Try grabbing wad name
            try
            {
                wad = args[0];
            }
            catch   //If the wad/mode couldn't be grabbed
            {
                Console.WriteLine("Please specify a wad file to convert!");
            }

            //Init empty variables, so they can be modified in the if condition below
            MemoryStream instream = new MemoryStream();
            BinaryReader reader = new BinaryReader(instream);
            byte[] inwad = new byte[0];

            if (!System.IO.File.Exists(wad))
            {
                Console.WriteLine("Wad file not found!");
                return;
            }
            else    //If the file exists
            {
                inwad = File.ReadAllBytes(wad);
                instream = new MemoryStream(inwad);  //Read the file into a memorystream
                reader = new BinaryReader(instream);  //Add a BinaryReader handle to the memorystream (allows for easier reading)
            }

            string header = new string(reader.ReadChars(5));    //Skip the header
            if (header != "KIWAD")
            {
                Console.WriteLine("This tool is only intended for KingsIsle .wad files");
                return; //Exit
            }

            Console.WriteLine("Processing wad...");

            int version = reader.ReadInt32();   //.wad version
            int FileCount = reader.ReadInt32(); //number of files

            FileList[] entries = new FileList[FileCount];


            if (version >= 2)
                reader.ReadByte();

            for (int i = 0; i < FileCount; i++)  //For every file entry in the wad, grab its offset, sizes, compression-status, crc, and name, and add that to an array
            {
                entries[i].Offset = reader.ReadUInt32();    //Read file offset
                entries[i].Size = reader.ReadUInt32(); ;  //Read size
                entries[i].CompressedSize = reader.ReadUInt32(); //Read compressed size
                entries[i].IsCompressed = reader.ReadBoolean(); //Read compression byte (whether the file is compressed or not)
                entries[i].CRC = reader.ReadUInt32();   //Read crc
                int namelen = reader.ReadInt32();   //Read length of name
                entries[i].Filename = new string(reader.ReadChars(namelen)).Replace("\0", String.Empty); //Read name (using specified name length), replace trailing null byte with empty
            }


            StringBuilder CRCLIST = new StringBuilder();
            object locker = new object();

            Parallel.For(0, entries.Length, i =>
            {
                MemoryStream instream_local = new MemoryStream(inwad);
                BinaryReader reader_local = new BinaryReader(instream_local);
                reader_local.BaseStream.Seek(entries[i].Offset, SeekOrigin.Begin); //Seek to the file entry

                if (reader_local.ReadInt32() != 0)    //Read 4 bytes of the file. If the bytes aren't 0 (the file exists)
                {
                    reader_local.BaseStream.Seek(entries[i].Offset, SeekOrigin.Begin); //Seek the stream back four bytes (because we just read 4 bytes of data, which would have been skipped if we didn't seek backwards

                    byte[] filemem = new byte[0];


                    if (entries[i].IsCompressed)   //If the file is marked as compressed
                    {
                        filemem = reader_local.ReadBytes((int)entries[i].CompressedSize);    //Create a memorystream for the file (size is the compressed filesize)
                        entries[i].Data = new byte[filemem.Length - 6];  //Copy the compressed data to the entry's data section
                        Array.Copy(filemem, 2, entries[i].Data, 0, filemem.Length - 6);
                        //filemem = Zlib.ZlibStream.UncompressBuffer(filemem);
                        using (var input = new System.IO.MemoryStream(entries[i].Data))
                        {
                            System.IO.Stream decompressor =
                                new DeflateStream(input, CompressionMode.Decompress);

                            byte[] working = new byte[1024];
                            using (var output = new MemoryStream())
                            {
                                using (decompressor)
                                {
                                    int n;
                                    while ((n = decompressor.Read(working, 0, working.Length)) != 0)
                                    {
                                        output.Write(working, 0, n);
                                    }
                                }
                                filemem = output.ToArray();
                            }
                        }
                        //System.IO.Compression.GZipStream
                    }
                    else    //If the file isn't compressed
                    {
                        filemem = reader_local.ReadBytes((int)entries[i].Size);    //Create a memorystream for the file (size is the uncompressed filesize)
                        entries[i].Data = filemem;  //Copy the data to the entry's data section
                    }
                    //System.IO.Compression.
                    entries[i].CRC = Crc32.Compute(filemem); //Replace the entries' crc with the CRC of the compressed data (KI are shit and use their own incompatible polynomials for their checksum, so we need to recalculate it with a standard polynomial)
                    
                }
                else    //If the first four bytes are 0 (dummy data)
                    Console.WriteLine("Missing File: " + entries[i].Filename);  //Inform the user, and move on to the next entry

                instream_local.Dispose();
                reader_local.Dispose();

            });
            byte[] outputfile = Zipper(entries);
            File.WriteAllBytes(wad + "_.zip", outputfile);
            MainTimer.Stop();
            Console.WriteLine("Total program runtime: {0}ms", MainTimer.ElapsedMilliseconds);
            return;


            
        }


        //Converts FileList to a zip file
        public static byte[] Zipper(FileList[] entries)
        {
            //Convert current time to DOS time (gross)
            //Dos time is the current time+date, compressed into just 4 bytes.
            //Due to the extreme compression, the time is only accurate to two seconds.
            //It also can't calculate dates before 1980, or after 2107, so expect it to break if you're a time-traveller (If you're using this tool after 2107, there's something wrong with *you*, not the tool)
            uint Time = 0;
            Time |= (uint)(DateTime.Now.Second / 2) << 0;
            Time |= (uint)DateTime.Now.Minute << 5;
            Time |= (uint)DateTime.Now.Hour << 11;
            Time |= (uint)DateTime.Now.Day << 16;
            Time |= (uint)DateTime.Now.Month << 21;
            Time |= (uint)(DateTime.Now.Year - 1980) << 25;
            byte[] timebytes = BitConverter.GetBytes(Time);

            List<byte> EntireZip = new List<byte>();    //Byte list to store the entire zip in memory (list for dynamic-ness)
            List<byte> ZipFooter = new List<byte>();    //Byte list to store the zip's footer
            for (int i = 0; i < entries.Length; i++)
            {
                int offset = EntireZip.Count;  //Save the current entry offset (for use in the headers)
                
                //Local_file stuff
                EntireZip.AddRange(new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00 });  //Add PK header (v20 minver, no flags)
                if (entries[i].IsCompressed)
                    EntireZip.AddRange(new byte[] { 0x08, 0x00 });  //Mark file as a deflate stream (that's how they're compressed)
                else    //If the file isn't compressed
                    EntireZip.AddRange(new byte[] { 0x00, 0x00 });  //Mark the file as non-compressed
                EntireZip.AddRange(timebytes);  //Add the time bytes (modified time of when the script started, because I cbf'd reading the actual time from the file attributes, plus processing time would increase)
                EntireZip.AddRange(BitConverter.GetBytes(entries[i].CRC));
                if (entries[i].IsCompressed)    //If the file is compressed
                    EntireZip.AddRange(BitConverter.GetBytes(entries[i].CompressedSize - 6));
                else
                    EntireZip.AddRange(BitConverter.GetBytes(entries[i].Size));
                EntireZip.AddRange(BitConverter.GetBytes(entries[i].Size));
                EntireZip.AddRange(BitConverter.GetBytes((short)entries[i].Filename.Length));
                EntireZip.AddRange(new byte[] { 0x00, 0x00 });  //Add two null bytes for extra data length (we don't have any extra data)
                EntireZip.AddRange(ASCIIEncoding.ASCII.GetBytes(entries[i].Filename));
                EntireZip.AddRange(entries[i].Data);    //Copy the file to the zip stream

                //I called it a footer, but it's officially called the 'Central File Directory' Sorry for any confusion
                ZipFooter.AddRange(new byte[] { 0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00 });  //Add Central File Directory Header magic, Viewer/Creator v20, flags 00 00
                if (entries[i].IsCompressed)
                    ZipFooter.AddRange(new byte[] { 0x08, 0x00 });  //Mark file as a deflate stream (that's how they're compressed in wads)
                else    //If the file isn't compressed
                    ZipFooter.AddRange(new byte[] { 0x00, 0x00 });  //Mark the file as non-compressed
                ZipFooter.AddRange(timebytes);  //Add the modified date/time
                ZipFooter.AddRange(BitConverter.GetBytes(entries[i].CRC));  //Add the CRC
                
                if (entries[i].IsCompressed)    //If the file is compressed
                    ZipFooter.AddRange(BitConverter.GetBytes(entries[i].CompressedSize - 6));   //Add the size of the data (-6 because the data includes a 2-byte zlib header and an adler32 hash (another 4 bytes))
                else    //If the file isn't compressed
                    ZipFooter.AddRange(BitConverter.GetBytes(entries[i].Size)); //Add the size of the uncompressed file (CompressedSize will be 0, which will cause errors)

                ZipFooter.AddRange(BitConverter.GetBytes(entries[i].Size)); //Add the extracted size
                ZipFooter.AddRange(BitConverter.GetBytes((short)entries[i].Filename.Length));
                ZipFooter.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00 });  //Extra field length, comment length, disk #, internal attribs (00 00 for binary), external attribs (02 00 00 00 seems ok?)
                ZipFooter.AddRange(BitConverter.GetBytes(offset));  //Add the offset for the file
                ZipFooter.AddRange(ASCIIEncoding.ASCII.GetBytes(entries[i].Filename));  //Add the filename
            }

            int FooterOffset = EntireZip.Count;   //Remember where the first byte of the footer is located in the zip

            EntireZip.AddRange(ZipFooter);  //Add the footer to the zip data
            
            
            //Now we need to add the zip64 footer, because some wads have a *lot* of files (eg; root.wad has over 73,000 files), and the max file-count for zip is 65535 (ffff)

            //Zip64 End of central directory
            EntireZip.AddRange(new byte[] { 0x50, 0x4B, 0x06, 0x06, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });  //PKZIOP 64 footer_header_marker, size of this field (excluding size and magic), version of zip (creator and viewer), disk number (0), disk number that contains directory (0)
            EntireZip.AddRange(BitConverter.GetBytes((long)entries.Length)); //Number of entries (including number of directories D:)
            EntireZip.AddRange(BitConverter.GetBytes((long)entries.Length));
            EntireZip.AddRange(BitConverter.GetBytes((long)ZipFooter.Count));
            EntireZip.AddRange(BitConverter.GetBytes((long)FooterOffset));

            //ZIP64 End of central directory locator
            EntireZip.AddRange(new byte[] { 0x50, 0x4B, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00 });  //magic, disk with this stuff on it
            EntireZip.AddRange(BitConverter.GetBytes((long)(FooterOffset + ZipFooter.Count)));  //Offset of this is after the footer?
            EntireZip.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });  //Number of disks (0)

            //End of central directory
            EntireZip.AddRange(new byte[] { 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00 });  //Footer_footer, number of disks, disk the footer is located on (all 0 because we ain't splittin nothin')
            if (entries.Length >= 65535)    //If the max files is beyond the max file-count storable in the zip footer (65535 is ffff), set the filecount to ffff (even windows does this, so the filecount is probable just a legacy field)
                EntireZip.AddRange(new byte[] { 0xff, 0xff, 0xff, 0xff });
            else
            {
                EntireZip.AddRange(BitConverter.GetBytes((ushort)entries.Length));  //Add number of files in this disk of archive (we only have one 'disk', so just do the total filecount)
                EntireZip.AddRange(BitConverter.GetBytes((ushort)entries.Length));  //Add number of files in entire archive
            }
            EntireZip.AddRange(BitConverter.GetBytes(ZipFooter.Count));
            EntireZip.AddRange(BitConverter.GetBytes(FooterOffset));
            EntireZip.AddRange(new byte[] { 0x00, 0x00 });

            return EntireZip.ToArray();
        }


        //https://github.com/damieng/DamienGKit/blob/master/CSharp/DamienG.Library/Security/Cryptography/Crc32.cs

        /// <summary>
        /// Implements a 32-bit CRC hash algorithm compatible with Zip etc.
        /// </summary>
        /// <remarks>
        /// Crc32 should only be used for backward compatibility with older file formats
        /// and algorithms. It is not secure enough for new applications.
        /// If you need to call multiple times for the same data either use the HashAlgorithm
        /// interface or remember that the result of one Compute call needs to be ~ (XOR) before
        /// being passed in as the seed for the next Compute call.
        /// </remarks>
        public sealed class Crc32 : HashAlgorithm
        {
            public const UInt32 DefaultPolynomial = 0xedb88320u;
            public const UInt32 DefaultSeed = 0xffffffffu;

            static UInt32[] defaultTable;

            readonly UInt32 seed;
            readonly UInt32[] table;
            UInt32 hash;

            public Crc32()
                : this(DefaultPolynomial, DefaultSeed)
            {
            }

            public Crc32(UInt32 polynomial, UInt32 seed)
            {
                if (!BitConverter.IsLittleEndian)
                    throw new PlatformNotSupportedException("Not supported on Big Endian processors");

                table = InitializeTable(polynomial);
                this.seed = hash = seed;
            }

            public override void Initialize()
            {
                hash = seed;
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                hash = CalculateHash(table, hash, array, ibStart, cbSize);
            }

            protected override byte[] HashFinal()
            {
                var hashBuffer = UInt32ToBigEndianBytes(~hash);
                HashValue = hashBuffer;
                return hashBuffer;
            }

            public override int HashSize { get { return 32; } }

            public static UInt32 Compute(byte[] buffer)
            {
                return Compute(DefaultSeed, buffer);
            }

            public static UInt32 Compute(UInt32 seed, byte[] buffer)
            {
                return Compute(DefaultPolynomial, seed, buffer);
            }

            public static UInt32 Compute(UInt32 polynomial, UInt32 seed, byte[] buffer)
            {
                return ~CalculateHash(InitializeTable(polynomial), seed, buffer, 0, buffer.Length);
            }

            static UInt32[] InitializeTable(UInt32 polynomial)
            {
                if (polynomial == DefaultPolynomial && defaultTable != null)
                    return defaultTable;

                var createTable = new UInt32[256];
                for (var i = 0; i < 256; i++)
                {
                    var entry = (UInt32)i;
                    for (var j = 0; j < 8; j++)
                        if ((entry & 1) == 1)
                            entry = (entry >> 1) ^ polynomial;
                        else
                            entry = entry >> 1;
                    createTable[i] = entry;
                }

                if (polynomial == DefaultPolynomial)
                    defaultTable = createTable;

                return createTable;
            }

            static UInt32 CalculateHash(UInt32[] table, UInt32 seed, IList<byte> buffer, int start, int size)
            {
                var hash = seed;
                for (var i = start; i < start + size; i++)
                    hash = (hash >> 8) ^ table[buffer[i] ^ hash & 0xff];
                return hash;
            }

            static byte[] UInt32ToBigEndianBytes(UInt32 uint32)
            {
                var result = BitConverter.GetBytes(uint32);

                if (BitConverter.IsLittleEndian)
                    Array.Reverse(result);

                return result;
            }
        }

    }
}
