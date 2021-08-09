using System;
using System.Threading.Tasks;
using CommandLine;

namespace EasyHash.ConsoleApp
{
    class Program
    {
        public class Options
        {
            [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
            public bool Verbose { get; set; }

            [Option('p', "path", Required = true)]
            public string Path { get; set; }
        }

        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(async o =>
                {
                    var cracker = new Cracker(o.Path, (s) =>
                    {
                        if (o.Verbose)
                        {
                            Console.WriteLine(s);
                        }
                    });

                    try
                    {
                        var result = await cracker.FindPassword("123tes");
                        Console.WriteLine(result);
                        Console.WriteLine("THE END");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        Console.WriteLine(e.StackTrace);
                    }
                });
        }
    }
}