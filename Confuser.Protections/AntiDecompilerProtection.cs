using Confuser.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Linq;

namespace Confuser.Protections
{
    internal class AntiDecompilerProtection : Protection
    {
        public override string Name { get { return "Anti-Decompiler Protection"; } }

        public override string Description { get { return "Protects against reverse engineering tools like ILSpy, dnSpy by injecting invalid IL instructions and obfuscating code structure"; } }

        public override string Id { get { return "anti decompiler"; } }
        public override string FullId { get { return "Ki.AntiDecompilerProtection"; } }

        public override ProtectionPreset Preset { get { return ProtectionPreset.Aggressive; } }

        protected override void Initialize(ConfuserContext context) {}

        protected override void PopulatePipeline(ProtectionPipeline pipeline)
        {
            pipeline.InsertPostStage(PipelineStage.ProcessModule, new AntiDecompilerPhase(this));
        }

        class AntiDecompilerPhase : ProtectionPhase
        {
            private readonly AntiDecompilerProtection _parent;

            public AntiDecompilerPhase(AntiDecompilerProtection parent) : base(parent)
            {
                _parent = parent;
            }

            public override ProtectionTargets Targets{ get { return ProtectionTargets.Methods; } }

            public override string Name { get { return "Anti Decompiler"; } }

            protected override void Execute(ConfuserContext context, ProtectionParameters parameters)
            {
                foreach (var method in parameters.Targets.OfType<MethodDef>())
                {
                    if (!method.HasBody) continue;

                    InsertInvalidIL(method);

                    CorruptExceptionHandlers(method);

                    ObfuscateMethodBody(method);
                }
            }

            private void InsertInvalidIL(MethodDef method)
            {
                var body = method.Body;
                var instr = body.Instructions;

                // Create a branching chain that confuses flow analysis
                var target = instr[0];
                var branch1 = Instruction.Create(OpCodes.Br_S, target);
                var branch2 = Instruction.Create(OpCodes.Br_S, branch1);
                var branch3 = Instruction.Create(OpCodes.Br_S, branch2);

                instr.Insert(0, branch3);
                instr.Insert(1, branch2);
                instr.Insert(2, branch1);

                // Insert unpaired leave instruction (invalid outside try block)
                instr.Insert(3, Instruction.Create(OpCodes.Leave, target));

                // Insert invalid switch with mismatched target count
                var switchInst = Instruction.Create(OpCodes.Switch, new Instruction[] { target, target });
                instr.Insert(4, Instruction.Create(OpCodes.Ldc_I4, 0));
                instr.Insert(5, switchInst);
            }

            private void CorruptExceptionHandlers(MethodDef method)
            {
                if (!method.Body.HasExceptionHandlers) return;
                
                foreach (var handler in method.Body.ExceptionHandlers)
                {
                    handler.HandlerEnd = handler.HandlerStart;
                    handler.TryEnd = handler.TryStart;
                }
            }

            private void ObfuscateMethodBody(MethodDef method)
            {
                var instructions = method.Body.Instructions;

                instructions.Insert(0, Instruction.Create(OpCodes.Nop));
                instructions.Insert(1, Instruction.Create(OpCodes.Nop));
            }
        }
    }
}