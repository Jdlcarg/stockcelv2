
import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Header from "@/components/layout/header";
import Sidebar from "@/components/layout/sidebar";
import MobileNav from "@/components/layout/mobile-nav";
import Footer from "@/components/layout/footer";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { AlertCircle, Clock, Calendar, CheckCircle, XCircle, Settings, Save, RefreshCw } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";

export default function CashScheduleConfig() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [config, setConfig] = useState({
    autoOpenEnabled: false,
    autoCloseEnabled: false,
    openHour: 9,
    openMinute: 0,
    closeHour: 18,
    closeMinute: 0,
    activeDays: "1,2,3,4,5,6,7",
    timezone: "America/Argentina/Buenos_Aires",
  });

  // Get current configuration
  const { data: currentConfig, isLoading } = useQuery({
    queryKey: ["/api/cash-schedule/config", user?.clientId],
    queryFn: async () => {
      const response = await fetch(`/api/cash-schedule/config?clientId=${user?.clientId}`);
      if (!response.ok) throw new Error('Failed to fetch configuration');
      return response.json();
    },
    enabled: !!user?.clientId,
  });

  // Removed scheduledOps query - now using config directly for consistency

  // Get automation service status
  const { data: serviceStatus } = useQuery({
    queryKey: ["/api/cash-schedule/service-status"],
    queryFn: async () => {
      const response = await fetch("/api/cash-schedule/service-status");
      if (!response.ok) throw new Error('Failed to fetch service status');
      return response.json();
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Get operations log
  const { data: operationsLog } = useQuery({
    queryKey: ["/api/cash-schedule/log", user?.clientId],
    queryFn: async () => {
      const response = await fetch(`/api/cash-schedule/log?clientId=${user?.clientId}&limit=20`);
      if (!response.ok) throw new Error('Failed to fetch operations log');
      return response.json();
    },
    enabled: !!user?.clientId,
  });

  // Update configuration mutation
  const updateConfigMutation = useMutation({
    mutationFn: async (newConfig: any) => {
      const response = await fetch("/api/cash-schedule/config", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-user-id": user?.id?.toString() || "",
        },
        body: JSON.stringify({
          clientId: user?.clientId,
          ...newConfig,
        }),
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Failed to update configuration');
      }
      
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Configuración guardada",
        description: "Los horarios de caja han sido actualizados exitosamente.",
      });
      // Invalidar queries relacionadas con horarios
      queryClient.invalidateQueries({ queryKey: ["/api/cash-schedule/config"] });
      queryClient.invalidateQueries({ queryKey: ["/api/cash-schedule/log"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Error al guardar",
        description: error.message || "No se pudo actualizar la configuración.",
      });
    },
  });

  // Set initial config when data loads
  useEffect(() => {
    if (currentConfig) {
      setConfig(currentConfig);
    }
  }, [currentConfig]);

  const handleSaveConfig = () => {
    updateConfigMutation.mutate(config);
  };

  const getDayName = (day: string) => {
    const days = {
      '1': 'Lun', '2': 'Mar', '3': 'Mié', '4': 'Jue', 
      '5': 'Vie', '6': 'Sáb', '7': 'Dom'
    };
    return days[day as keyof typeof days] || day;
  };

  const formatTime = (hour: number, minute: number) => {
    return `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
  };

  // Removed getOperationStatusBadge - no longer needed since we use config directly

  if (isLoading) {
    return (
      <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
        <Sidebar />
        <div className="flex-1 flex flex-col">
          <Header />
          <div className="flex-1 flex items-center justify-center">
            <div className="text-lg">Cargando configuración...</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 dark:from-gray-900 dark:to-gray-800 flex flex-col">
      <Header onMobileMenuToggle={() => setMobileNavOpen(true)} />
      <MobileNav open={mobileNavOpen} onOpenChange={setMobileNavOpen} />

      <div className="flex flex-1">
        <Sidebar />
        
        <main className="flex-1">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            
            {/* Header */}
            <div className="mb-8">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center">
                    <Clock className="mr-3 h-8 w-8 text-primary" />
                    Configuración de Horarios de Caja
                  </h1>
                  <p className="text-gray-600 dark:text-gray-300 mt-1">
                    Configure la apertura y cierre automático de caja con reportes
                  </p>
                </div>
                
                {/* Service Status */}
                <div className="flex items-center space-x-2">
                  <div className="flex items-center space-x-2">
                    {serviceStatus?.isRunning ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                    <span className="text-sm font-medium">
                      Servicio: {serviceStatus?.isRunning ? 'Activo' : 'Inactivo'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              
              {/* Configuration Panel */}
              <div className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Settings className="mr-2 h-5 w-5" />
                      Configuración de Horarios
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    
                    {/* Auto Open Configuration */}
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-lg font-medium">Apertura Automática</h3>
                          <p className="text-sm text-gray-600">Abrir caja automáticamente</p>
                        </div>
                        <Switch
                          checked={config.autoOpenEnabled}
                          onCheckedChange={(checked) => 
                            setConfig(prev => ({ ...prev, autoOpenEnabled: checked }))
                          }
                        />
                      </div>
                      
                      {config.autoOpenEnabled && (
                        <div className="grid grid-cols-2 gap-4 ml-4 p-4 bg-gray-50 rounded-lg">
                          <div>
                            <Label htmlFor="openHour">Hora</Label>
                            <Select
                              value={config.openHour.toString()}
                              onValueChange={(value) => 
                                setConfig(prev => ({ ...prev, openHour: parseInt(value) }))
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {Array.from({ length: 24 }, (_, i) => (
                                  <SelectItem key={i} value={i.toString()}>
                                    {i.toString().padStart(2, '0')}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <Label htmlFor="openMinute">Minutos</Label>
                            <Select
                              value={config.openMinute.toString()}
                              onValueChange={(value) => 
                                setConfig(prev => ({ ...prev, openMinute: parseInt(value) }))
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {[0, 15, 30, 45].map(minute => (
                                  <SelectItem key={minute} value={minute.toString()}>
                                    {minute.toString().padStart(2, '0')}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                      )}
                    </div>

                    <Separator />

                    {/* Auto Close Configuration */}
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-lg font-medium">Cierre Automático</h3>
                          <p className="text-sm text-gray-600">Cerrar caja y generar reporte automáticamente</p>
                        </div>
                        <Switch
                          checked={config.autoCloseEnabled}
                          onCheckedChange={(checked) => 
                            setConfig(prev => ({ ...prev, autoCloseEnabled: checked }))
                          }
                        />
                      </div>
                      
                      {config.autoCloseEnabled && (
                        <div className="grid grid-cols-2 gap-4 ml-4 p-4 bg-gray-50 rounded-lg">
                          <div>
                            <Label htmlFor="closeHour">Hora</Label>
                            <Select
                              value={config.closeHour.toString()}
                              onValueChange={(value) => 
                                setConfig(prev => ({ ...prev, closeHour: parseInt(value) }))
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {Array.from({ length: 24 }, (_, i) => (
                                  <SelectItem key={i} value={i.toString()}>
                                    {i.toString().padStart(2, '0')}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <Label htmlFor="closeMinute">Minutos</Label>
                            <Select
                              value={config.closeMinute.toString()}
                              onValueChange={(value) => 
                                setConfig(prev => ({ ...prev, closeMinute: parseInt(value) }))
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {[0, 15, 30, 45].map(minute => (
                                  <SelectItem key={minute} value={minute.toString()}>
                                    {minute.toString().padStart(2, '0')}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                      )}
                    </div>

                    <Separator />

                    {/* Active Days */}
                    <div className="space-y-4">
                      <div>
                        <h3 className="text-lg font-medium">Días Activos</h3>
                        <p className="text-sm text-gray-600">Seleccione los días de la semana</p>
                      </div>
                      
                      <div className="flex flex-wrap gap-2">
                        {['1', '2', '3', '4', '5', '6', '7'].map(day => {
                          const isActive = config.activeDays.split(',').includes(day);
                          return (
                            <Button
                              key={day}
                              variant={isActive ? "default" : "outline"}
                              size="sm"
                              onClick={() => {
                                const days = config.activeDays.split(',');
                                const newDays = isActive 
                                  ? days.filter(d => d !== day)
                                  : [...days, day];
                                setConfig(prev => ({ 
                                  ...prev, 
                                  activeDays: newDays.sort().join(',') 
                                }));
                              }}
                            >
                              {getDayName(day)}
                            </Button>
                          );
                        })}
                      </div>
                    </div>

                    <Separator />

                    {/* Save Button */}
                    <Button 
                      onClick={handleSaveConfig} 
                      className="w-full" 
                      disabled={updateConfigMutation.isPending}
                    >
                      {updateConfigMutation.isPending ? (
                        <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Save className="mr-2 h-4 w-4" />
                      )}
                      Guardar Configuración
                    </Button>
                  </CardContent>
                </Card>
              </div>

              {/* Status and Operations Panel */}
              <div className="space-y-6">
                
                {/* Current Schedule */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Calendar className="mr-2 h-5 w-5" />
                      Horario Actual
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="font-medium">Apertura:</span>
                        <div className="flex items-center space-x-2">
                          <span className="text-lg font-mono">
                            {formatTime(config.openHour, config.openMinute)}
                          </span>
                          {config.autoOpenEnabled ? (
                            <Badge variant="default">Activo</Badge>
                          ) : (
                            <Badge variant="secondary">Deshabilitado</Badge>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <span className="font-medium">Cierre:</span>
                        <div className="flex items-center space-x-2">
                          <span className="text-lg font-mono">
                            {formatTime(config.closeHour, config.closeMinute)}
                          </span>
                          {config.autoCloseEnabled ? (
                            <Badge variant="default">Activo</Badge>
                          ) : (
                            <Badge variant="secondary">Deshabilitado</Badge>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <span className="font-medium">Días activos:</span>
                        <div className="flex flex-wrap gap-1">
                          {config.activeDays.split(',').map(day => (
                            <Badge key={day} variant="outline" className="text-xs">
                              {getDayName(day)}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Next Operations - USAR EXACTAMENTE LOS MISMOS DATOS QUE HORARIO ACTUAL */}
                <Card>
                  <CardHeader>
                    <CardTitle>Próximas Operaciones</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {/* APERTURA - USAR CONFIG DIRECTAMENTE COMO EN HORARIO ACTUAL */}
                      {config.autoOpenEnabled && (
                        <div className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                          <div>
                            <div className="font-medium">🌅 Apertura Automática</div>
                            <div className="text-sm text-gray-600">
                              Configurado para las <span className="font-bold text-blue-600">
                                {formatTime(config.openHour, config.openMinute)}
                              </span> (Argentina)
                            </div>
                            <div className="text-xs text-gray-500">
                              Apertura diaria - ✅ Activo
                            </div>
                          </div>
                          <Badge variant="default">Programado hoy</Badge>
                        </div>
                      )}
                      
                      {/* CIERRE - USAR CONFIG DIRECTAMENTE COMO EN HORARIO ACTUAL */}
                      {config.autoCloseEnabled && (
                        <div className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                          <div>
                            <div className="font-medium">🌆 Cierre Automático</div>
                            <div className="text-sm text-gray-600">
                              Configurado para las <span className="font-bold text-blue-600">
                                {formatTime(config.closeHour, config.closeMinute)}
                              </span> (Argentina)
                            </div>
                            <div className="text-xs text-gray-500">
                              Cierre diario - ✅ Activo
                            </div>
                          </div>
                          <Badge variant="default">Programado hoy</Badge>
                        </div>
                      )}
                      
                      {/* MENSAJE SI NO HAY OPERACIONES ACTIVAS */}
                      {!config.autoOpenEnabled && !config.autoCloseEnabled && (
                        <div className="text-center text-gray-500 py-4">
                          No hay operaciones automáticas configuradas
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                {/* Operations Log */}
                {operationsLog && operationsLog.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Historial de Operaciones</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {operationsLog.map((log: any) => (
                          <div key={log.id} className="flex justify-between items-center p-2 text-sm border-b last:border-b-0">
                            <div>
                              <div className="font-medium">
                                {log.operationType === 'auto_open' ? 'Apertura' : 
                                 log.operationType === 'auto_close' ? 'Cierre' : 
                                 log.operationType}
                              </div>
                              <div className="text-xs text-gray-600">
                                {new Date(log.executedTime).toLocaleString('es-AR')}
                              </div>
                            </div>
                            <Badge 
                              variant={
                                log.status === 'success' ? 'default' :
                                log.status === 'failed' ? 'destructive' : 'secondary'
                              }
                              className="text-xs"
                            >
                              {log.status === 'success' ? 'Exitoso' :
                               log.status === 'failed' ? 'Error' : 'Omitido'}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Important Notice */}
                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Importante:</strong> Los reportes automáticos se generan al cerrar la caja 
                    automáticamente e incluyen toda la información del día: ventas, gastos, comisiones 
                    de vendedores y estadísticas completas.
                  </AlertDescription>
                </Alert>
              </div>
            </div>
          </div>
        </main>
      </div>
      <Footer />
    </div>
  );
}
